package server

import (
	_ "database/sql"
	"log"
	"os"
	"runtime"
	"strings"

	"net/http"
	_ "net/http/pprof"

	ldapserver "github.com/cloudldap/ldapserver"
	"github.com/comail/colog"
	"github.com/go-ldap/ldap"
	"github.com/pkg/errors"
)

var (
	maxRetry = 10
)

type ServerConfig struct {
	BindAddress        string
	LogLevel           string
	PProfServer        string
	GoMaxProcs         int
	DefaultBackendLDAP string
	BackendLDAP        BackendLDAPConfig
	TimoutInSeconds    int
}

type BackendLDAPConfig map[string]string

func (s ServerConfig) LookupBackend(dn string) string {
	dn = strings.ToLower(dn)
	for k, v := range s.BackendLDAP {
		if strings.HasSuffix(dn, k) {
			return v
		}
	}
	return s.DefaultBackendLDAP
}

type Server struct {
	config   *ServerConfig
	internal *ldapserver.Server
}

func NewServer(c *ServerConfig) *Server {
	return &Server{
		config: c,
	}
}

func (s *Server) Config() *ServerConfig {
	return s.config
}

func (s *Server) Start() {
	// Init logging
	cl := colog.NewCoLog(os.Stdout, "worker", log.LstdFlags)

	level := strings.ToUpper(s.config.LogLevel)
	if level == "ERROR" {
		cl.SetMinLevel(colog.LError)
		colog.SetMinLevel(colog.LError)
	} else if level == "WARN" {
		cl.SetMinLevel(colog.LWarning)
		colog.SetMinLevel(colog.LWarning)
	} else if level == "INFO" {
		cl.SetMinLevel(colog.LInfo)
		colog.SetMinLevel(colog.LInfo)
	} else if level == "DEBUG" {
		cl.SetMinLevel(colog.LDebug)
		colog.SetMinLevel(colog.LDebug)
	}
	cl.SetDefaultLevel(colog.LDebug)
	colog.SetDefaultLevel(colog.LDebug)
	cl.SetFormatter(&colog.StdFormatter{
		Colors: true,
		Flag:   log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile,
	})
	colog.SetFormatter(&colog.StdFormatter{
		Colors: true,
		Flag:   log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile,
	})
	colog.Register()

	if _, ok := ldapserver.Logger.(*log.Logger); ok {
		ldapserver.Logger = cl.NewLogger()
	}

	// Launch pprof
	if s.config.PProfServer != "" {
		go func() {
			log.Println(http.ListenAndServe(s.config.PProfServer, nil))
		}()
	}

	// Init GOMAXPROCS
	if s.config.GoMaxProcs > 0 {
		log.Printf("info: Setup GOMAXPROCS: %d. NumCPU: %d\n", s.config.GoMaxProcs, runtime.NumCPU())
		runtime.GOMAXPROCS(s.config.GoMaxProcs)
	} else {
		log.Printf("info: Setup GOMAXPROCS with NumCPU: %d\n", runtime.NumCPU())
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	//Create a new LDAP Server
	server := ldapserver.NewServer()
	s.internal = server

	//Create routes bindings
	routes := ldapserver.NewRouteMux()
	routes.NotFound(handleNotFound)
	routes.Abandon(handleAbandon)
	routes.Bind(NewHandler(s, handleBind))
	routes.Compare(handleNotSupported)
	routes.Add(handleNotSupported)
	routes.Delete(handleNotSupported)
	routes.Modify(handleNotSupported)
	routes.ModifyDN(handleNotSupported)
	routes.Search(NewHandler(s, handleSearch))

	//Attach routes to server
	server.Handle(routes)

	// Optional config
	server.MaxRequestSize = 5 * 1024 * 1024 // 5MB

	log.Printf("info: Starting cloudldap on %s", s.config.BindAddress)

	// listen and serve
	server.ListenAndServe(s.config.BindAddress)
}

func (s *Server) Stop() {
	s.internal.Stop()
}

func (s *Server) GetBackendConn(m *ldapserver.Message, dn string) (*ldap.Conn, error) {
	r := m.Client.GetCustomResource()

	if r == nil {
		// Create new connection
		address := s.config.LookupBackend(dn)

		conn, err := ldap.Dial("tcp", address)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to connect to backend LDAP: %s", address)
		}

		// attach the backend connection to the current client
		m.Client.SetCustomResource(conn)

		return conn, nil
	}

	conn, ok := r.(*ldap.Conn)
	if !ok {
		return nil, errors.Errorf("Unexpected connection: %v", r)
	}

	return conn, nil
}

func NewHandler(s *Server, handler func(s *Server, w ldapserver.ResponseWriter, r *ldapserver.Message)) func(w ldapserver.ResponseWriter, r *ldapserver.Message) {
	return func(w ldapserver.ResponseWriter, r *ldapserver.Message) {
		handler(s, w, r)
	}
}

func handleNotSupported(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	res := ldapserver.NewResponse(ldap.LDAPResultInsufficientAccessRights)
	w.Write(res)
}

func handleNotFound(w ldapserver.ResponseWriter, r *ldapserver.Message) {
	switch r.ProtocolOpType() {
	case ldapserver.ApplicationBindRequest:
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)
		res.SetDiagnosticMessage("Default binding behavior set to return Success")

		w.Write(res)

	default:
		res := ldapserver.NewResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Operation not implemented by server")
		w.Write(res)
	}
}

func handleAbandon(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	var req = m.GetAbandonRequest()
	// retrieve the request to abandon, and send a abort signal to it
	if requestToAbandon, ok := m.Client.GetMessageByID(int(req)); ok {
		requestToAbandon.Abandon()
		log.Printf("info: Abandon signal sent to request processor [messageID=%d]", int(req))
	}
}

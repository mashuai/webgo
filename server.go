package web

import (
	"bytes"
	"code.google.com/p/go.net/websocket"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"path"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ServerConfig is configuration for server objects.
// 服务器配置
type ServerConfig struct {
	StaticDir    string //静态文件夹
	Addr         string //地址
	Port         int    //端口
	CookieSecret string //cookie secret
	RecoverPanic bool   //异常处理
	Profiler     bool   //开启性能监控
}

// Server represents a web.go server.
// 服务
type Server struct {
	Config *ServerConfig          //服务器设置
	routes []route                //路由
	Logger *log.Logger            //日志
	Env    map[string]interface{} //环境变量
	//save the listener so it can be closed
	l net.Listener //保存监听器,以便关掉
}

// 初始化server
func NewServer() *Server {
	return &Server{
		Config: Config,
		Logger: log.New(os.Stdout, "", log.Ldate|log.Ltime),
		Env:    map[string]interface{}{},
	}
}

//初始化server参数
func (s *Server) initServer() {
	if s.Config == nil {
		s.Config = &ServerConfig{}
	}

	if s.Logger == nil {
		s.Logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	}
}

//访问路由
type route struct {
	r           string         //路由参数
	cr          *regexp.Regexp //编译后的正则表达式
	method      string         //请求方法,POST,GET等
	handler     reflect.Value  //处理请求的方法
	httpHandler http.Handler   //处理的http方法
}

//添加路由
func (s *Server) addRoute(r string, method string, handler interface{}) {
	cr, err := regexp.Compile(r)
	if err != nil {
		s.Logger.Printf("Error in route regex %q\n", r)
		return
	}

	switch handler.(type) {
	case http.Handler:
		s.routes = append(s.routes, route{r: r, cr: cr, method: method, httpHandler: handler.(http.Handler)})
	case reflect.Value:
		fv := handler.(reflect.Value)
		s.routes = append(s.routes, route{r: r, cr: cr, method: method, handler: fv})
	default:
		fv := reflect.ValueOf(handler)
		s.routes = append(s.routes, route{r: r, cr: cr, method: method, handler: fv})
	}
}

// ServeHTTP is the interface method for Go's http server package
//实现了Handler 接口,可以处理各种请求
func (s *Server) ServeHTTP(c http.ResponseWriter, req *http.Request) {
	s.Process(c, req)
}

// Process invokes the routing system for server s
//根据路由处理请求
func (s *Server) Process(c http.ResponseWriter, req *http.Request) {
	route := s.routeHandler(req, c)
	if route != nil {
		route.httpHandler.ServeHTTP(c, req)
	}
}

// 添加各种路由,及其对应的方法
// Get adds a handler for the 'GET' http method for server s.
func (s *Server) Get(route string, handler interface{}) {
	s.addRoute(route, "GET", handler)
}

// Post adds a handler for the 'POST' http method for server s.
func (s *Server) Post(route string, handler interface{}) {
	s.addRoute(route, "POST", handler)
}

// Put adds a handler for the 'PUT' http method for server s.
func (s *Server) Put(route string, handler interface{}) {
	s.addRoute(route, "PUT", handler)
}

// Delete adds a handler for the 'DELETE' http method for server s.
func (s *Server) Delete(route string, handler interface{}) {
	s.addRoute(route, "DELETE", handler)
}

// Match adds a handler for an arbitrary http method for server s.
func (s *Server) Match(method string, route string, handler interface{}) {
	s.addRoute(route, method, handler)
}

//Adds a custom handler. Only for webserver mode. Will have no effect when running as FCGI or SCGI.
func (s *Server) Handler(route string, method string, httpHandler http.Handler) {
	s.addRoute(route, method, httpHandler)
}

//Adds a handler for websockets. Only for webserver mode. Will have no effect when running as FCGI or SCGI.
func (s *Server) Websocket(route string, httpHandler websocket.Handler) {
	s.addRoute(route, "GET", httpHandler)
}

// Run starts the web application and serves HTTP requests for s
// 启动运行
func (s *Server) Run(addr string) {
	s.initServer()

	mux := http.NewServeMux()
	if s.Config.Profiler {
		mux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
		mux.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
	}
	mux.Handle("/", s) //将所有的请求发送给s,由ServerHTTP处理

	s.Logger.Printf("web.go serving %s\n", addr)

	l, err := net.Listen("tcp", addr) //监听请求
	if err != nil {
		log.Fatal("ListenAndServe:", err)
	}
	s.l = l
	err = http.Serve(s.l, mux) //开始接收请求
	s.l.Close()
}

// RunFcgi starts the web application and serves FastCGI requests for s.
// 运行fcgi模式
func (s *Server) RunFcgi(addr string) {
	s.initServer()
	s.Logger.Printf("web.go serving fcgi %s\n", addr)
	s.listenAndServeFcgi(addr)
}

// RunScgi starts the web application and serves SCGI requests for s.
// 运行scgi模式
func (s *Server) RunScgi(addr string) {
	s.initServer()
	s.Logger.Printf("web.go serving scgi %s\n", addr)
	s.listenAndServeScgi(addr)
}

// RunTLS starts the web application and serves HTTPS requests for s.
// 运行tls模式
func (s *Server) RunTLS(addr string, config *tls.Config) error {
	s.initServer()
	mux := http.NewServeMux()
	mux.Handle("/", s)
	l, err := tls.Listen("tcp", addr, config)
	if err != nil {
		log.Fatal("Listen:", err)
		return err
	}

	s.l = l
	return http.Serve(s.l, mux)
}

// Close stops server s.
// 关闭服务器
func (s *Server) Close() {
	if s.l != nil {
		s.l.Close()
	}
}

// safelyCall invokes `function` in recover block
// 调用handler,先检测是否有panic,直接返回执行结果
func (s *Server) safelyCall(function reflect.Value, args []reflect.Value) (resp []reflect.Value, e interface{}) {
	defer func() {
		if err := recover(); err != nil {
			if !s.Config.RecoverPanic {
				// go back to panic
				panic(err)
			} else {
				e = err
				resp = nil
				s.Logger.Println("Handler crashed with error", err)
				for i := 1; ; i += 1 {
					_, file, line, ok := runtime.Caller(i)
					if !ok {
						break
					}
					s.Logger.Println(file, line)
				}
			}
		}
	}()
	return function.Call(args), nil
}

// requiresContext determines whether 'handlerType' contains
// an argument to 'web.Ctx' as its first argument
// 检测方法是否需要context
func requiresContext(handlerType reflect.Type) bool {
	//if the method doesn't take arguments, no
	if handlerType.NumIn() == 0 {
		return false
	}

	//if the first argument is not a pointer, no
	a0 := handlerType.In(0)
	if a0.Kind() != reflect.Ptr {
		return false
	}
	//if the first argument is a context, yes
	if a0.Elem() == contextType {
		return true
	}

	return false
}

// tryServingFile attempts to serve a static file, and returns
// whether or not the operation is successful.
// It checks the following directories for the file, in order:
// 1) Config.StaticDir
// 2) The 'static' directory in the parent directory of the executable.
// 3) The 'static' directory in the current working directory
// 返回静态文件
func (s *Server) tryServingFile(name string, req *http.Request, w http.ResponseWriter) bool {
	//try to serve a static file
	if s.Config.StaticDir != "" {
		staticFile := path.Join(s.Config.StaticDir, name)
		if fileExists(staticFile) {
			http.ServeFile(w, req, staticFile)
			return true
		}
	} else {
		for _, staticDir := range defaultStaticDirs {
			staticFile := path.Join(staticDir, name)
			if fileExists(staticFile) {
				http.ServeFile(w, req, staticFile)
				return true
			}
		}
	}
	return false
}

// 记录访问日志
func (s *Server) logRequest(ctx Context, sTime time.Time) {
	//log the request
	var logEntry bytes.Buffer
	req := ctx.Request
	requestPath := req.URL.Path

	duration := time.Now().Sub(sTime)
	var client string

	// We suppose RemoteAddr is of the form Ip:Port as specified in the Request
	// documentation at http://golang.org/pkg/net/http/#Request
	pos := strings.LastIndex(req.RemoteAddr, ":")
	if pos > 0 {
		client = req.RemoteAddr[0:pos]
	} else {
		client = req.RemoteAddr
	}

	fmt.Fprintf(&logEntry, "%s - \033[32;1m %s %s\033[0m - %v", client, req.Method, requestPath, duration)

	if len(ctx.Params) > 0 {
		fmt.Fprintf(&logEntry, " - \033[37;1mParams: %v\033[0m\n", ctx.Params)
	}

	ctx.Server.Logger.Print(logEntry.String())

}

// the main route handler in web.go
// Tries to handle the given request.
// Finds the route matching the request, and execute the callback associated
// with it.  In case of custom http handlers, this function returns an "unused"
// route. The caller is then responsible for calling the httpHandler associated
// with the returned route.
// web.go主要的处理函数,首先找到,匹配的路由,然后调用相关的函数,
// 如果函数是http的,则返回为处理,通过调用的Process函数处理
func (s *Server) routeHandler(req *http.Request, w http.ResponseWriter) (unused *route) {
	requestPath := req.URL.Path                    //得到请求url
	ctx := Context{req, map[string]string{}, s, w} //初始化server上下文

	//set some default headers
	//设置server类型
	ctx.SetHeader("Server", "web.go", true)
	tm := time.Now().UTC()

	//ignore errors from ParseForm because it's usually harmless.
	// 解析参数
	req.ParseForm()
	if len(req.Form) > 0 {
		for k, v := range req.Form {
			ctx.Params[k] = v[0]
		}
	}

	defer s.logRequest(ctx, tm) //记录访问日志
	//设置服务器时间
	ctx.SetHeader("Date", webTime(tm), true)
	// 尝试返回静态文件
	if req.Method == "GET" || req.Method == "HEAD" {
		if s.tryServingFile(requestPath, req, w) {
			return
		}
	}

	//Set the default content-type
	// 设置默认的content-type

	ctx.SetHeader("Content-Type", "text/html; charset=utf-8", true)
	// 通过route获取处理方法
	for i := 0; i < len(s.routes); i++ {
		route := s.routes[i]
		cr := route.cr
		//if the methods don't match, skip this handler (except HEAD can be used in place of GET)
		// 如果路由方法不同,跳过这个路由,如果是HEAD,检测路由是否是GET
		if req.Method != route.method && !(req.Method == "HEAD" && route.method == "GET") {
			continue
		}
		// 是否跟路由的正则匹配
		if !cr.MatchString(requestPath) {
			continue
		}
		match := cr.FindStringSubmatch(requestPath)
		//检测最左匹配是否跟路径相同大小
		if len(match[0]) != len(requestPath) {
			continue
		}
		// 检测httpHandler,如果不空则直接返回.
		if route.httpHandler != nil {
			unused = &route
			// We can not handle custom http handlers here, give back to the caller.
			return
		}

		var args []reflect.Value
		handlerType := route.handler.Type()
		//检测方法是否需要context
		if requiresContext(handlerType) {
			args = append(args, reflect.ValueOf(&ctx))
		}
		//将匹配的参数传给相应的函数
		for _, arg := range match[1:] {
			args = append(args, reflect.ValueOf(arg))
		}
		//调用处理函数
		ret, err := s.safelyCall(route.handler, args)
		if err != nil {
			//there was an error or panic while calling the handler
			ctx.Abort(500, "Server Error")
		}
		if len(ret) == 0 {
			return
		}
		//处理成功,返回相应数据
		//大多数情况下都是直接在函数中返回了

		sval := ret[0]

		var content []byte

		if sval.Kind() == reflect.String {
			content = []byte(sval.String())
		} else if sval.Kind() == reflect.Slice && sval.Type().Elem().Kind() == reflect.Uint8 {
			content = sval.Interface().([]byte)
		}
		ctx.SetHeader("Content-Length", strconv.Itoa(len(content)), true)
		_, err = ctx.ResponseWriter.Write(content)
		if err != nil {
			ctx.Server.Logger.Println("Error during write: ", err)
		}
		return
	}

	// try serving index.html or index.htm
	// 出问题返回index文件.
	if req.Method == "GET" || req.Method == "HEAD" {
		if s.tryServingFile(path.Join(requestPath, "index.html"), req, w) {
			return
		} else if s.tryServingFile(path.Join(requestPath, "index.htm"), req, w) {
			return
		}
	}
	ctx.Abort(404, "Page not found")
	return
}

// SetLogger sets the logger for server s
// 设置日志记录.
func (s *Server) SetLogger(logger *log.Logger) {
	s.Logger = logger
}

/*
Práctica SC 22/23

Funcionalidad a implementar

Estudiante: FERNANDO AUGUSTO MARINA URRIOLA
*/
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
	//"github.com/zserge/lorca" //Para usar IU. Primero descargar lorca con: go get github.com/zserge/lorca
)

/************************
CONFIGURACION PRÁCTICA
*************************/

// Indica el tipo de interfaz que usará la aplicación:
// 0: solo test
// 1: Linea de comandos
// 2: Interfaz gráfica
func tipoUI() int {
	return 0
}

/**********************
FUNCIONES A IMPLEMENTAR
***********************/

/**********************
-------SERVIDOR--------
***********************/

// Guarda la base de datos en un fichero de disco
func (dSrv *db) guardar(nomFich string, clave []byte) {
	b, err := json.Marshal(dSrv) // serializar a JSON
	chk(err)
	err = ioutil.WriteFile(nomFich, b, 0777) // escribir en fichero
	chk(err)
}

// Carga la base de datos de un fichero de disco
func (dSrv *db) cargar(nomFich string, clave []byte) {
	b, err := ioutil.ReadFile(nomFich) // leer fichero
	chk(err)
	err = json.Unmarshal(b, dSrv) // deserializar de JSON obteniendo la BD en memoria
	chk(err)
}

// Realiza el registro de usuario
func (dSrv *db) registrarUsuario(login, contr string) bool {
	u, ok := dSrv.Creds[login] // comprobar si existe el usuario

	if ok { //existe y es distinto
		if strings.Compare(contr, u.Contraseña) != 0 { // comparar contraseña
			return false
		}
	} else { //no existe, registro
		dSrv.Creds[login] = auth{login, contr} // añadir a la BD
	}
	return true
}

// Autenticación según la sección del API a la que se quiere acceder
func (dSrv *db) puedeAcceder(login, contr string, token string, comando string) bool {
	accesoOk := true

	return accesoOk
}

// Acciones a ejecutar al iniciar el servidor
func (dSrv *db) AccionPreStart() {
	//...
}

// Acciones a ejecutar antes de realizar un comando
func (dSrv *db) AccionPreCommando(w http.ResponseWriter, req *http.Request) {
	//...
}

// Manejador de commandos extras
func (dSrv *db) CommandosExtras(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Comando sin implementar: %s \n", req.Form.Get("cmd"))
}

// Acciones a ejecutar despues de realizar un comando
func (dSrv *db) AccionPostCommando(w http.ResponseWriter, req *http.Request) {
	//...
}

// Acciones a ejecutar antes de apagar el servidor
func (dSrv *db) AccionPreStop() {
	//...
}

// Obtener clave maestra para el cifrado (tamaño de 32 bytes -> 256bits)
func (dSrv *db) ClaveMaestra() []byte {
	return []byte("---Esto es una clave fija---    ")
}

// Obtener clave admin para login
func (dSrv *db) ClaveAdminInicial() string {
	return "soy la clave inicial de admin"
}

// Obtener nombre usuario admin para login
func (dSrv *db) UserAdmin() string {
	return "Admin"
}

// Obtiene el token actual de un cliente. Cadena vacia si no tiene o está caducado
func (dSrv *db) GetUserToken(usr string) string {
	return ""
}

/**********************
-------CLIENTE--------
***********************/

// Obtener clave admin para login en servidor
func (dCli *dataCliente) ClaveAdminInicial() string {
	return "soy la clave inicial de admin"
}

// Devuelve el usuario actual para login en servidor
func (dCli *dataCliente) UserActual() string {
	return dCli.usrActual
}

// Devuelve la clave del usuario actual
func (dCli *dataCliente) ClaveActual() string {
	return dCli.passActual
}

// Devuelve el token de acceso del usuario actual
func (dCli *dataCliente) TokenActual() string {
	return dCli.tokenActual
}

/**********
INTERFACES
***********/
func cmdLogin(cli *http.Client, usr string, pass string) string {
	data := url.Values{}
	//autenticamos todas las peticiones
	data.Set("usr", usr)
	data.Set("pass", pass)
	data.Set("cmd", "LOGIN") // comando (string)

	var buffer bytes.Buffer

	r, err := cli.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	fmt.Print("Respuesta --> ")
	_, err = io.Copy(&buffer, r.Body)

	retorno := buffer.String()

	return retorno
}

//Función que desarrolla la interfaz por linea de comandos en caso de ser este el modo de implemantación
func cmdIniIUI(cli *http.Client) {
	fmt.Println("¡Bienvenido a mi programa!")

	var accion, accion2 int

	//Bucle del menú inicial
	for {
		accion = accionMenuInicial()
		fmt.Println("Has elegido:" + fmt.Sprint(accion))
		fmt.Println("")
		if accion == 0 {
			break
		}
		switch accion {
		case 1:
			var usr, pass string

			fmt.Println("Usuario:")
			fmt.Scanln(&usr)
			fmt.Println("Contraseña:")
			fmt.Scanln(&pass)

			//iniciar sesión con cmdLogin(cli, usr, pass)
			fmt.Println("Iniciando sesión con '" + usr + "' y  contraseña '" + pass + "'")

			//Crear estrucutra de datos de incio de sesión del cliente
			// clienteData = dataCliente{
			// 	usrActual:   "",
			// 	passActual: "",
			// 	tokenActual: "",
			// }

			//Bucle del menú principal
			for {
				accion2 = accionMenuSecundario()
				fmt.Println("Has elegido:" + fmt.Sprint(accion2))
				fmt.Println("")
				if accion2 == 0 {
					break
				}
				switch accion2 {
				case 1:
					fmt.Println("-----------")
					fmt.Println("|   HOLA   |")
					fmt.Println("-----------")
					fmt.Println("")
				case 2:
					fmt.Println("-----------")
					fmt.Println("|   ADIOS  |")
					fmt.Println("-----------")
					fmt.Println("")
				}
			}
		}
	}

	cmdSalir(cli)
}

func accionMenuInicial() int {
	fmt.Println("")
	fmt.Println("---------------****---------------")
	fmt.Println("Acciones:")
	fmt.Println("1) Login")
	fmt.Println("0) Salir")
	fmt.Println("----------------------------------")
	fmt.Println("¿Qué deseas hacer? (0,1)")

	var opcion int
	fmt.Scanln(&opcion)

	return opcion
}

func accionMenuSecundario() int {
	fmt.Println("")
	fmt.Println("---------------****---------------")
	fmt.Println("Acciones:")
	fmt.Println("1) Dí 'HOLA'")
	fmt.Println("2) Dí 'ADIOS'")
	fmt.Println("0) Volver")
	fmt.Println("----------------------------------")
	fmt.Println("¿Qué deseas hacer? (0,1,2)")

	var opcion int
	fmt.Scanln(&opcion)

	return opcion
}

//Función que desarrolla la interfaz gráfica en caso de ser este el modo de implemantación
//Recuerda descargar el módulo de go con:
// go get github.com/zserge/lorca
func cmdIniGUI(cli *http.Client) {
	/*
		args := []string{}
		if runtime.GOOS == "linux" {
			args = append(args, "--class=Lorca")
		}
		ui, err := lorca.New("", "", 480, 320, args...)
		if err != nil {
			log.Fatal(err)
		}
		defer ui.Close()

		// A simple way to know when UI is ready (uses body.onload event in JS)
		ui.Bind("start", func() {
			log.Println("UI is ready")
		})

		// Load HTML.
		b, err := ioutil.ReadFile("./www/index.html") // just pass the file name
		if err != nil {
			fmt.Print(err)
		}
		html := string(b) // convert content to a 'string'
		ui.Load("data:text/html," + url.PathEscape(html))

		// You may use console.log to debug your JS code, it will be printed via
		// log.Println(). Also exceptions are printed in a similar manner.
		ui.Eval(`
			console.log("Hello, world!");
		`)

		// Wait until the interrupt signal arrives or browser window is closed
		sigc := make(chan os.Signal)
		signal.Notify(sigc, os.Interrupt)
		select {
		case <-sigc:
		case <-ui.Done():
		}

		log.Println("exiting...")
	*/
}

/******
DATOS
*******/

// contenedor de la base de datos
type db struct {
	Pacs  map[uint]paciente  // lista de pacientes indexados por ID
	Docs  map[uint]doctor    // lista de doctores indexados por ID
	Hists map[uint]historial // lista de historiales indexados por ID
	Creds map[string]auth    // lista de credenciales indexadas por Login
}

// datos relativos a pacientes
type paciente struct {
	ID         uint // identificador primario de paciente
	Nombre     string
	Apellidos  string
	Nacimiento time.Time
	Sexo       string //H-> Mombre, M-> Mujer
}

// datos relativos al personal médico
type doctor struct {
	ID           uint // identificador primario del doctor
	Nombre       string
	Apellidos    string
	Especialidad string
	Login        string // referencia a auth
}

// datos relativos a historiales
type historial struct {
	ID       uint      // identificador primario de la entrada de historial
	Fecha    time.Time // fecha de creación/modificación
	Doctor   uint      // referencia a un doctor
	Paciente uint      // referencia a un paciente
	Datos    string    // contenido de la entrada del historial (texto libre)
}

// datos relativos a la autentificación (credenciales)
type auth struct {
	Login      string // nombre de entrada e identificador primario de credenciales
	Contraseña string // contraseña (en claro, se debe modificar...)
}

//Estos son los datos que almacena el cliente en memoría para trabajar
type dataCliente struct {
	usrActual   string // nombre de usuario introducido por el usuario
	passActual  string // contraseña introducida por el usuario
	tokenActual string // token proporcionado por el servidor para autenticación de las peticiones
}

/***********
UTILIDADES
************/

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

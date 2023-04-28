/*
Práctica SC 22/23

# Funcionalidad a implementar

Estudiante: FERNANDO AUGUSTO MARINA URRIOLA
*/
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"os"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
	"golang.org/x/crypto/scrypt"
	"compress/zlib"
	"encoding/base64"
)

/************************
CONFIGURACION PRÁCTICA
*************************/

// Indica el tipo de interfaz que usará la aplicación:
// 0: solo test
// 1: Linea de comandos
// 2: Interfaz gráfica
func tipoUI() int {
	return 1
}

/**********************
FUNCIONES A IMPLEMENTAR
***********************/
func guardarIVEnArchivo(filename string, iv []byte) error {
    // Abrir el archivo para escritura
    file, err := os.Create(filename)
    chk(err)
    defer file.Close()
    // Escribir los bytes en el archivo
    _, err = file.Write(iv)
    if err != nil {
        return err
    }
    return nil
}

// función para cifrar (con AES en este caso), adjunta el IV al principio
func encrypt(data, key []byte) (out []byte) {
	filename := "iv.txt"
	var iv [16]byte
	// Generar un IV utilizando la función rand
	_, err := rand.Read(iv[:])
	chk(err)
	// Llamar a la función para guardar el IV en el archivo
	err = guardarIVEnArchivo(filename, iv[:])
	chk(err)
	fmt.Println("El IV se ha generado y guardado correctamente en el archivo.")
	blk, err := aes.NewCipher(key)         // cifrador en bloque (AES), usa key
	chk(err)                               // comprobamos el error
	out = make([]byte, 16+len(data))       // inicializamos out con la longitud correcta (IV + datos)
										   // si no, me da error: "output smaller than input"
	copy(out[:16], iv[:])                  // copiamos el IV al principio de out
	ctr := cipher.NewCTR(blk, out[:16])    // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)       // ciframos los datos
	// XORKey.. va byte por byte haciendo una operacion XOR con el slice y
	// los bytes de cifrado de la clave
	return
}


// función para descifrar (con AES en este caso)
func decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	// si no le sumo el len de b me da error: "output smaller than input"
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	// XORKey.. va byte por byte haciendo una operacion XOR con el slice y
	// los bytes de cifrado de la clave
	ctr.XORKeyStream(out, data[16:])     // (doble cifrado) los datos
	return
}

// función para comprimir
func compress(data []byte) []byte {
	var b bytes.Buffer      // b contendrá los datos comprimidos (tamaño variable)
	w := zlib.NewWriter(&b) // escritor que comprime sobre b
	w.Write(data)           // escribimos los datos
	w.Close()               // cerramos el escritor (buffering)
	return b.Bytes()        // devolvemos los datos comprimidos
}

// función para descomprimir
func decompress(data []byte) []byte {
	var b bytes.Buffer                              // b contendrá los datos descomprimidos
	r, err := zlib.NewReader(bytes.NewReader(data)) // lector descomprime al leer
	chk(err)                                        // comprobamos el error
	io.Copy(&b, r)                                  // copiamos del descompresor (r) al buffer (b)
	r.Close()                                       // cerramos el lector (buffering)
	return b.Bytes()                                // devolvemos los datos descomprimidos
}

/**********************
-------SERVIDOR--------
***********************/
func (dSrv *db) guardar(nomFich string, clave []byte) {
	b, err := json.Marshal(dSrv) // serializar a JSON
	chk(err)
	b = encrypt(b, clave) 
	b = compress(b)
	err = ioutil.WriteFile(nomFich, b, 0777) // escribir en fichero, el string b se guarda en el fichero nomFich
	chk(err)
}

// Carga la base de datos de un fichero de disco
func (dSrv *db) cargar(nomFich string, clave []byte) {
	b, err := ioutil.ReadFile(nomFich) // leer fichero
	chk(err)
	b = decompress(b) // descomprimir
	b = decrypt(b, clave) // descifrar
	err = json.Unmarshal(b, dSrv) // deserializar de JSON obteniendo la BD en memoria
	chk(err)
}

// Realiza el registro de usuario
func (dSrv *db) registrarUsuario(login, contr string) bool {
	_, ok := dSrv.Creds[login] //comprueba si existe el usuario en la base de datos
	if ok {
		// si existe, no se registra
		return false
	} else {
		//se registra el usuario
		var Hash []byte                                           // se crea un slice de bytes para el hash
		Sal := make([]byte, 16)                                   // se reserva un espacio de 16 bytes para la sal
		rand.Read(Sal)                                            // se crea la sal aleatoriamente
		Hash, _ = scrypt.Key([]byte(contr), Sal, 32768, 8, 1, 32) // se hashea la contraseña con la sal
		dSrv.Creds[login] = auth{login, Hash, Sal}                // se añade a la base de datos
	}
	return true
}

// Autenticación según la sección del API a la que se quiere acceder
func (dSrv *db) puedeAcceder(login, contr string, token string, comando string) bool {
	equalHashBooleanForAllUsers := false
	accesoOk := false
	adminBool := false
	u, ok := dSrv.Creds[login] // se comprueba el usuario
	hash, _ := scrypt.Key([]byte(contr), u.Sal,  32768, 8, 1, 32) // se hashea de nuevo la contraseña con la sal que se ha creado antes
	//cuando se inicie el programa por primera vez no entrara en este if ya que primero se debe 
	// registrar el administrador
	if ok {
		if !bytes.Equal(u.Hash, hash) { // se compara si el u.hash de la bbdd y el que se ha generado ahora son iguales
			//si son iguales la autenticación es igual a true
			equalHashBooleanForAllUsers = true
		}
	}
	if login == dSrv.UserAdmin() { 
		// si este login de admin es igual que el de la base de datos, el admin es igual a true
		adminBool = true
	}

	// con el switch se controla el comando enviado por el servidor
	switch comando {
		// solo podrá acceder el usuario administrador con la contraseña inicial y si 
		// aún no se ha registrado ningún usuario administrador.
		case "BD_INI":
			_, existeAdmin := dSrv.Creds[dSrv.UserAdmin()] // verifica si hay un admin
			// si no hay un administrador y no se ha registrado admin, continua
			if adminBool && !existeAdmin {            
				if contr == dSrv.ClaveAdminInicial() {
					accesoOk = true // si la contraseña introducida es igual que la contraseña del administrador, puede acceder
				}
			} else {
				accesoOk = false
			}
			//solo puede acceder el administrador
		case "SALIR":
			accesoOk = equalHashBooleanForAllUsers && adminBool
		case "DOC_REG":
			accesoOk = equalHashBooleanForAllUsers && adminBool
		default://resto de comandos
			accesoOk = equalHashBooleanForAllUsers
	}
	return accesoOk
}



// Variables globales
var adminPassGlobal string
var claveMaestraGlobal []byte

// Acciones a ejecutar al iniciar el servidor
func (dSrv *db) AccionPreStart() {
	// crear una clave maestra para poder descifrar todos los datos
	claveMaestraGlobal = make([]byte, 32) // se reserva un espacio de 32 bytes y se rellena con valores aleatorios
	rand.Read(claveMaestraGlobal)

	passAdminLocal := make([]byte, 32) // se reserva un espacio de 32 bytes y se rellena con valores aleatorios
	rand.Read(passAdminLocal)
	adminPassGlobal = base64.StdEncoding.EncodeToString([]byte(passAdminLocal)) // se codifica la clave que se ha creado anteriormente 
	// se codifica la clave que se ha creado anteriormente
	fmt.Printf("La clave inicial es: " + adminPassGlobal + " ") // se muestra la contraseña por terminal
	fmt.Printf("")

	// se crea un fichero para guardar la clave maestra
	// si existe este fichero se lee de aqui
	maestraPassGlobal, err := os.ReadFile("maestra.txt") // si existe este fichero se lee de aqui

	if err != nil {
		_, err := os.Create("maestra.txt") // cuando no existe ningun fichero se crea uno
		chk(err)

		maestraPassGlobal = make([]byte, 32) // se reserva un espacio de 32 bytes y se rellena con valores aleatorios
		rand.Read(maestraPassGlobal)

		err2 := ioutil.WriteFile("maestra.txt", maestraPassGlobal, 0777) // se hashea esta clave
		chk(err2)
	}
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
	return claveMaestraGlobal
}

// Obtener clave admin para login
func (dSrv *db) ClaveAdminInicial() string {
	return adminPassGlobal
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
	return adminPassGlobal
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

/*
*********
INTERFACES
**********
*/
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

// Función que desarrolla la interfaz por linea de comandos en caso de ser este el modo de implemantación
func cmdIniIUI(cli *http.Client) {
	fmt.Println("¡Bienvenido a mi programa!")

	var accion, accion2 int
	for {
		accion = accionMenuInicial()
		fmt.Println("Has seleccionado:" + fmt.Sprint(accion))
		fmt.Println("")
		if accion == 0 { // si se selecciona salir, se cierra la aplicacion
			fmt.Println("Aplicación Cerrada")
			os.Exit(0)
		}
		switch accion {
		case 1:
			var usr, pass string // se inicializan las variables usuario y contraseña

			fmt.Println("Usuario:")
			fmt.Scanln(&usr)
			fmt.Println("Contraseña:")
			fmt.Scanln(&pass)
			fmt.Println("Iniciando sesión con '" + usr + "' y  contraseña '" + pass + "'")
			clienteData = dataCliente{
				usrActual:   usr,
				tokenActual: "",
				passActual:  pass,
			}

			for { // si la contraseña es correcta se inicializa el for
				accion2 = accionMenuSecundario() // se abre el menu 2
				fmt.Println("Has seleccionado:" + fmt.Sprint(accion2))
				fmt.Println("")
				if accion2 == 0 {
					// si se selecciona salir, se cierra la aplicacion
					break
				}
				switch accion2 {
				case 1:
					cmdBDIni(cli)
				case 2:
					cmdBDImp(cli)
				case 3:
					var idPac, idMed, observaciones string
					fmt.Println("Id Paciente:")
					fmt.Scanln(&idPac)
					fmt.Println("Id Medico:")
					fmt.Scanln(&idMed)
					fmt.Println("Observaciones:")
					fmt.Scanln(&observaciones)
					cmdHistReg(cli, idPac, idMed, observaciones)
					cmdBDGrabar(cli, "datos.db")

				case 4:
					var id, nombre, apellidos, especialidad, us, contra string
					fmt.Println("Id:")
					fmt.Scanln(&id)
					fmt.Println("Nombre:")
					fmt.Scanln(&nombre)
					fmt.Println("Apellidos:")
					fmt.Scanln(&apellidos)
					fmt.Println("Especialidad:")
					fmt.Scanln(&especialidad)
					fmt.Println("Usuario:")
					fmt.Scanln(&us)
					fmt.Println("Contraseña:")
					fmt.Scanln(&contra)
					fmt.Println("Registrando al medico'" + nombre + "''" + apellidos + "'")
					cmdDocReg(cli, id, nombre, apellidos, especialidad, us, contra)
					cmdBDGrabar(cli, "datos.db")
				case 5:
					var id, nombre, apellidos, fecha, genero string
					fmt.Println("Id:")
					fmt.Scanln(&id)
					fmt.Println("Nombre:")
					fmt.Scanln(&nombre)
					fmt.Println("Apellidos:")
					fmt.Scanln(&apellidos)
					fmt.Println("Fecha de Nacimiento:")
					fmt.Scanln(&fecha)
					fmt.Println("Hombre o Mujer (M/H):")
					fmt.Scanln(&genero)
					cmdPacReg(cli, id, nombre, apellidos, fecha, genero)
					cmdBDGrabar(cli, "datos.db")
				case 6:
					cmdSalir(cli)
				}
			}
		}
	}
}

func accionMenuInicial() int {
	fmt.Println("PROGRAMA DE GESTIÓN DE HISTORIALES MÉDICOS")
	fmt.Println("Hecho por: Fernando Marina Urriola")
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
	fmt.Println("MENÚ PRINCIPAL")
	fmt.Println("")
	fmt.Println("1) Iniciar base de datos")
	fmt.Println("2) Imprimir la base de datos")
	fmt.Println("3) Añadir historial")
	fmt.Println("4) Registrar doctor")
	fmt.Println("5) Añadir paciente")
	fmt.Println("6) Salir")
	fmt.Println("0) Volver")

	var opcion int
	fmt.Scanln(&opcion)

	return opcion
}

// Función que desarrolla la interfaz gráfica en caso de ser este el modo de implemantación
// Recuerda descargar el módulo de go con:
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
	Sal		   []byte // sal para anyadir a la contrasenya
	Hash       []byte // hash para anyadir a la contrasenya
}

// Estos son los datos que almacena el cliente en memoría para trabajar
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

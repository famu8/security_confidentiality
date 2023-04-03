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
	//aqui hacer un swicth para implementar el tipo de operacion que el usuario quisiera realizar
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
	/*
	// crear una clave maestra para poder descifrar todos los datos
	claveMaestraGlobal = make([]byte, 32) // se reserva un espacio de 32 bytes y se rellena con valores aleatorios
	rand.Read(claveMaestraGlobal)

	local_pass_admin := make([]byte, 32) // se reserva un espacio de 32 bytes y se rellena con valores aleatorios
	rand.Read(local_pass_admin)
	adminPassGlobal = base64.StdEncoding.EncodeToString([]byte(local_pass_admin)) // se codifica la clave que se ha creado anteriormente // se codifica la cave que se ha creado anteriormente

	fmt.Printf("La clave inicial es: " + adminPassGlobal + " ") // se muestra la contraseña por terminal
	fmt.Printf("")
	global_pass_maestra, err := os.ReadFile("fichero.txt") // si existe este fichero se lee de aqui

	if err != nil {
		_, err := os.Create("fichero.txt") // cuando no existe ningun fichero se crea uno
		chk(err)

		global_pass_maestra = make([]byte, 32) // se reserva un espacio de 32 bytes y se rellena con valores aleatorios
		rand.Read(global_pass_maestra)

		err2 := ioutil.WriteFile("fichero.txt", global_pass_maestra, 0777) // se hashea esta clave
		chk(err2)
	}*/
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

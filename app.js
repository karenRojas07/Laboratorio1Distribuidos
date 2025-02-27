// app.js
const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcrypt'); // <--- Requerir bcrypt
const app = express();
const PORT = 3000;

// Configurar EJS como motor de plantillas
app.set('view engine', 'ejs');

const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Configurar el transporte de correo (usando un servicio SMTP como Gmail)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'limaskharool@gmail.com',
    pass: 'lbnz eqbm clau axoa'
  }
});


// Middleware de sesión
app.use(session({
  secret: 'MI_SECRETO_SEGURO', // Cambia esta cadena por algo más seguro
  resave: false,
  saveUninitialized: false
}));

// Middleware para parsear JSON y formularios
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Conexión a la base de datos
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'loginNodeJs'
});

db.connect((err) => {
  if (err) {
    console.error('Error al conectar a la base de datos:', err);
    process.exit(1);
  }
  console.log('Conectado a la base de datos MySQL.');

  // CREACIÓN DE TABLAS (si no existen)
  const createUsuariosTable = `
    CREATE TABLE IF NOT EXISTS Usuarios (
      id_usuario INT AUTO_INCREMENT PRIMARY KEY,
      nombre_usuario VARCHAR(50) NOT NULL,
      correo_electronico VARCHAR(100) NOT NULL,
      contrasena_hashed VARCHAR(255) NOT NULL,
      intentos_fallidos INT DEFAULT 0,
      bloqueado BOOLEAN DEFAULT FALSE
    )
  `;

  const createRolesTable = `
    CREATE TABLE IF NOT EXISTS Roles (
      id_rol INT AUTO_INCREMENT PRIMARY KEY,
      nombre_rol VARCHAR(50) NOT NULL
    )
  `;

  const createUsuariosRolesTable = `
    CREATE TABLE IF NOT EXISTS Usuarios_Roles (
      id_usuario INT NOT NULL,
      id_rol INT NOT NULL,
      FOREIGN KEY (id_usuario) REFERENCES Usuarios(id_usuario) ON DELETE CASCADE,
      FOREIGN KEY (id_rol) REFERENCES Roles(id_rol) ON DELETE CASCADE,
      PRIMARY KEY (id_usuario, id_rol)
    )
  `;

  db.query(createUsuariosTable, (error) => {
    if (error) {
      console.error('Error al crear/verificar tabla Usuarios:', error);
    } else {
      console.log('Tabla Usuarios creada/verificada correctamente.');
    }
  });

  db.query(createRolesTable, (error) => {
    if (error) {
      console.error('Error al crear/verificar tabla Roles:', error);
    } else {
      console.log('Tabla Roles creada/verificada correctamente.');
    }
  });

  db.query(createUsuariosRolesTable, (error) => {
    if (error) {
      console.error('Error al crear/verificar tabla Usuarios_Roles:', error);
    } else {
      console.log('Tabla Usuarios_Roles creada/verificada correctamente.');
    }
  });
});

// ============================================
// Rutas de vistas (GET)
// ============================================

// GET / -> Página principal (login)
app.get('/', (req, res) => {
  // Si ya existe req.session.user, redirigir a welcome
  if (req.session.user) {
    return res.redirect('/welcome');
  }
  res.render('index');
});

// GET /register -> Formulario de registro
app.get('/register', (req, res) => {
  res.render('register');
});

// GET /welcome -> Página de bienvenida
app.get('/welcome', (req, res) => {
  // Verifica si hay un usuario en sesión
  if (!req.session.user) {
    return res.redirect('/');
  }
  // Pasa el usuario a la vista welcome.ejs
  res.render('welcome', { user: req.session.user });
});


// Ruta para mostrar el formulario de recuperación de contraseña
app.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});

// Ruta para enviar el token al correo del usuario
// Ruta para enviar el token al correo del usuario
app.post('/forgot-password', (req, res) => {
  const { correo_electronico } = req.body;

  if (!correo_electronico) {
    return res.status(400).json({ message: 'El correo electrónico es requerido.' });
  }

  // Verificar si el correo existe en la base de datos
  const findUserQuery = 'SELECT * FROM Usuarios WHERE correo_electronico = ?';
  db.query(findUserQuery, [correo_electronico], (err, results) => {
    if (err) {
      console.error('Error al buscar usuario:', err);
      return res.status(500).json({ message: 'Error en el servidor.' });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: 'Correo electrónico no encontrado.' });
    }

    const user = results[0];

    // Generar un token único para la recuperación
    const token = generateToken();

    // Enviar correo con el token de recuperación
    sendRecoveryEmail(correo_electronico, token);

    // Confirmación de envío
    res.status(200).json({ message: 'Se ha enviado un correo con el token de recuperación.' });
  });
});


///FUNCIONES

// fucion  para almacenar token
function storeToken(token) {
  const expirationTime = Date.now() + 5 * 60 * 1000; // 5 minutos en milisegundos
  localStorage.setItem('resetPasswordToken', token);
  localStorage.setItem('tokenExpiration', expirationTime);
}

// fucion  para validar token
function isTokenValid() {
  const expirationTime = localStorage.getItem('tokenExpiration');
  return Date.now() < expirationTime;
}


// Función para generar un token único para la recuperación de contraseña
function generateToken() {
  return crypto.randomBytes(32).toString('hex'); // Genera un token aleatorio de 64 caracteres
}

// Función para el envio de correos para recuperar contraseña
function sendRecoveryEmail(correo_electronico, token) {
  const mailOptions = {
    from: 'tu-email@gmail.com', // Dirección de correo que envía el mensaje
    to: correo_electronico,
    subject: 'Recuperación de Contraseña',
    text: `Para restablecer tu contraseña, usa el siguiente token: ${token}\nEste token es válido solo por 5 minutos.`
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error('Error al enviar el correo:', err);
    } else {
      console.log('Correo enviado: ' + info.response);
    }
  });
}



// ============================================
// Rutas de lógica (POST)
// ============================================

// Registrar usuario
app.post('/register', (req, res) => {
  const { nombre_usuario, correo_electronico, contrasena } = req.body;

  if (!nombre_usuario || !correo_electronico || !contrasena) {
    return res
      .status(400)
      .json({ message: 'Faltan datos (nombre_usuario, correo_electronico, contrasena).' });
  }

  const checkQuery = `
    SELECT *
    FROM Usuarios
    WHERE nombre_usuario = ?
       OR correo_electronico = ?
  `;

  db.query(checkQuery, [nombre_usuario, correo_electronico], (err, results) => {
    if (err) {
      console.error('Error al verificar usuario:', err);
      return res.status(500).json({ message: 'Error en el servidor' });
    }

    if (results.length > 0) {
      return res
        .status(400)
        .json({ message: 'El nombre de usuario o correo ya está registrado.' });
    }

    // Hashear la contraseña usando bcrypt
    bcrypt.hash(contrasena, 10, (errHash, contrasenaHasheada) => {
      if (errHash) {
        console.error('Error al hashear la contraseña:', errHash);
        return res.status(500).json({ message: 'Error en el servidor' });
      }

      const insertQuery = `
        INSERT INTO Usuarios (nombre_usuario, correo_electronico, contrasena_hashed)
        VALUES (?, ?, ?)
      `;
      db.query(insertQuery, [nombre_usuario, correo_electronico, contrasenaHasheada], (err2) => {
        if (err2) {
          console.error('Error al registrar usuario:', err2);
          return res.status(500).json({ message: 'Error en el servidor' });
        }

        // Redirigimos luego de registro exitoso
        return res.redirect('/');
      });
    });
  });
});

// Iniciar sesión
app.post('/login', (req, res) => {
  const { nombre_usuario, contrasena } = req.body;

  if (!nombre_usuario || !contrasena) {
    return res.status(400).json({ message: 'Se requieren nombre_usuario y contrasena.' });
  }

  const findUserQuery = 'SELECT * FROM Usuarios WHERE nombre_usuario = ?';
  db.query(findUserQuery, [nombre_usuario], (err, results) => {
    if (err) {
      console.error('Error en el servidor:', err);
      return res.status(500).json({ message: 'Error en el servidor' });
    }

    if (results.length === 0) {
      return res
        .status(401)
        .json({ message: 'Credenciales inválidas (usuario no encontrado).' });
    }

    const user = results[0];

    // Comparar contraseñas usando bcrypt
    bcrypt.compare(contrasena, user.contrasena_hashed, (errCompare, isMatch) => {
      if (errCompare) {
        console.error('Error al comparar contraseñas:', errCompare);
        return res.status(500).json({ message: 'Error en el servidor' });
      }

      if (!isMatch) {
        return res
          .status(401)
          .json({ message: 'Credenciales inválidas (contraseña incorrecta).' });
      }

      // Guardar user en la sesión
      req.session.user = {
        id_usuario: user.id_usuario,
        nombre_usuario: user.nombre_usuario,
        correo_electronico: user.correo_electronico,
        bloqueado: user.bloqueado
      };

      // Redirigir a welcome
      return res.redirect('/welcome');
    });
  });
});

// Cerrar sesión
app.post('/logout', (req, res) => {
  // Destruir la sesión
  req.session.destroy((err) => {
    if (err) {
      console.error('Error al destruir sesión:', err);
      // Redirige o envía error
      return res.redirect('/');
    }
    res.redirect('/'); // Redirigimos al login ("/") después de cerrar sesión
  });
});

// Obtener todos los usuarios
app.get('/users', (req, res) => {
  db.query('SELECT * FROM Usuarios', (err, results) => {
    if (err) {
      console.error('Error al obtener usuarios:', err);
      return res.status(500).json({ message: 'Error en el servidor' });
    }
    return res.status(200).json(results);
  });
});

// Ruta para mostrar el formulario de cambio de contraseña
app.get('/reset-password/:token', (req, res) => {
  const token = req.params.token;

  // Verificar si el token existe en localStorage y es válido
  const storedToken = localStorage.getItem('resetPasswordToken');
  const tokenExpiration = localStorage.getItem('tokenExpiration');

  // Validar si el token es el mismo y no ha expirado
  if (storedToken && storedToken === token && Date.now() < tokenExpiration) {
    // Renderizar la página de cambio de contraseña
    res.render('reset-password', { token: token });
  } else {
    res.redirect('/forgot-password'); // Si no es válido, redirigir a la página de recuperar contraseña
  }
});


// ============================================
// Iniciar el servidor
// ============================================
app.listen(PORT, () => {
  console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
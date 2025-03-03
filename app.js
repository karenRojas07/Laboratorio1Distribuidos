const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcrypt');
const app = express();
const PORT = 3000;
const blockedUntilMap = {};


app.set('view engine', 'ejs');

const nodemailer = require('nodemailer');
const crypto = require('crypto');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'limaskharool@gmail.com',
    pass: 'lbnz eqbm clau axoa'
  }
});


app.use(session({
  secret: 'MI_SECRETO_SEGURO', // Cambia esta cadena por algo más seguro
  resave: false,
  saveUninitialized: false
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
  if (req.session.user) {
    return res.redirect('/welcome');
  }

  // Consulta todos los usuarios para listarlos en el select
  const getUsersQuery = 'SELECT id_usuario, nombre_usuario FROM Usuarios';

  db.query(getUsersQuery, (err, results) => {
    if (err) {
      console.error('Error al obtener usuarios:', err);
      return res.status(500).send('Error en el servidor');
    }

    // results tendrá [{id_usuario:1, nombre_usuario:"Juan"}, {id_usuario:2, nombre_usuario:"María"}, ...]
    res.render('index', { users: results });
  });
});

// GET /register -> Formulario de registro
app.get('/register', (req, res) => {
  res.render('register');
});

// GET /api/get-roles/:userId -> Retorna en JSON los roles asignados a un usuario
app.get('/api/get-roles/:userId', (req, res) => {
  const userId = req.params.userId;

  // Consulta los roles que tiene asignado este usuario
  const query = `
    SELECT r.id_rol, r.nombre_rol
    FROM Usuarios_Roles ur
    JOIN Roles r ON ur.id_rol = r.id_rol
    WHERE ur.id_usuario = ?
  `;

  db.query(query, [userId], (err, roles) => {
    if (err) {
      console.error('Error al obtener roles del usuario:', err);
      return res.status(500).json({ message: 'Error en el servidor' });
    }

    // Retornamos la lista de roles en formato JSON
    res.json(roles);
    // Por ejemplo: [{id_rol:1, nombre_rol:'Administrador'}, {id_rol:2, nombre_rol:'Usuario'}, ...]
  });
});

// GET /assign-roles -> Formulario para asignar roles
app.get('/assign-roles', (req, res) => {
  // 1. Verifica que el usuario esté autenticado
  if (!req.session.user) {
    return res.redirect('/');
  }

  // Verifica que el rol sea "admin"
  if (req.session.user.rol !== '1') {
    return res.status(403).send('No tienes permiso para acceder a esta ruta.');
  }

  // 2. Obtén todos los usuarios y roles desde la base de datos
  const getUsersQuery = 'SELECT id_usuario, nombre_usuario FROM Usuarios';
  const getRolesQuery = 'SELECT id_rol, nombre_rol FROM Roles';

  db.query(getUsersQuery, (errUsers, users) => {
    if (errUsers) {
      console.error('Error al obtener usuarios:', errUsers);
      return res.status(500).send('Error en el servidor');
    }

    db.query(getRolesQuery, (errRoles, roles) => {
      if (errRoles) {
        console.error('Error al obtener roles:', errRoles);
        return res.status(500).send('Error en el servidor');
      }

      // 3. Renderiza la vista "assign-roles.ejs" pasando la lista de usuarios y roles
      res.render('assign-roles', { users, roles });
    });
  });
});

// Ruta para mostrar el formulario de cambio de contraseña
app.get('/reset-password', (req, res) => {
  res.render('reset-password');
});

// GET /welcome -> Página de bienvenida
app.get('/welcome', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/');
  }
  res.render('welcome', { user: req.session.user });
});

// Ruta para mostrar el formulario de recuperación de contraseña
app.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});

// GET /create-role -> Página para crear un nuevo rol
app.get('/create-role', (req, res) => {
  // Opcional: verifica si el usuario está en sesión
  if (!req.session.user) {
    return res.redirect('/');
  }

  // Verifica que el rol sea "admin"
  if (req.session.user.rol !== '1') {
    return res.status(403).send('No tienes permiso para acceder a esta ruta.');
  }

  // Renderiza la vista "create-role.ejs"
  res.render('create-role');
});


// Función para generar un token único de 6 caracteres
function generateToken() {
  return Math.random().toString(36).substr(2, 6);
}

// Función para enviar el correo con el token
function sendRecoveryEmail(correo_electronico, token) {
  const mailOptions = {
    from: 'tu-email@gmail.com',
    to: correo_electronico,
    subject: 'Recuperación de Contraseña',
    text: `Para restablecer tu contraseña, usa el siguiente enlace: ${process.env.BASE_URL}/reset-password\nEste token es válido solo por 5 minutos.\nToken: ${token}`
  };

  transporter.sendMail(mailOptions, (err, info) => {
    if (err) {
      console.error('Error al enviar el correo:', err);
    } else {
      console.log('Correo enviado: ' + info.response);
    }
  });
}

// POST /create-role -> Procesa la creación de un nuevo rol
app.post('/create-role', (req, res) => {
  // (1) Validar sesión (opcional, si quieres restringir el acceso)
  if (!req.session.user) {
    return res.redirect('/');
  }

  const { nombre_rol } = req.body;

  // (2) Verificar que venga el nombre del rol
  if (!nombre_rol) {
    return res.status(400).send('Falta el nombre del rol.');
  }

  // (3) Insertar el nuevo rol en la tabla Roles
  const insertRoleQuery = `
    INSERT INTO Roles (nombre_rol)
    VALUES (?)
  `;

  db.query(insertRoleQuery, [nombre_rol], (err, result) => {
    if (err) {
      console.error('Error al crear el rol:', err);
      return res.status(500).send('Error en el servidor');
    }

    // (4) Redirigir a la página de bienvenida
    res.redirect('/welcome');
  });
});

// Ruta para enviar el token al correo del usuario
app.post('/forgot-password', (req, res) => {
  const { correo_electronico } = req.body;

  if (!correo_electronico) {
    return res.status(400).json({ message: 'El correo electrónico es requerido.' });
  }

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

    // Generar un token único de 6 caracteres para la recuperación
    const token = generateToken();
    const expirationTime = Date.now() + 5 * 60 * 1000; // 5 minutos de expiración

    const storeTokenQuery = 'INSERT INTO PasswordResetTokens (correo_electronico, token, expiration_time) VALUES (?, ?, ?)';
    db.query(storeTokenQuery, [correo_electronico, token, expirationTime], (err2) => {
      if (err2) {
        console.error('Error al almacenar token en la base de datos:', err2);
        return res.status(500).json({ message: 'Error en el servidor' });
      }

      sendRecoveryEmail(correo_electronico, token);

      res.status(200).json({ message: 'Se ha enviado un correo con el token de recuperación.' });
    });
  });
});

// Ruta para registrar un nuevo usuario
app.post('/register', (req, res) => {
  const { nombre_usuario, correo_electronico, contrasena } = req.body;

  // Validar los datos del formulario
  if (!nombre_usuario || !correo_electronico || !contrasena) {
    return res.status(400).json({ message: 'Faltan datos (nombre_usuario, correo_electronico, contrasena).' });
  }

  // Verificar si el correo o nombre de usuario ya están registrados
  const checkQuery = `
    SELECT *
    FROM Usuarios
    WHERE nombre_usuario = ?
       OR correo_electronico = ?
  `;

  db.query(checkQuery, [nombre_usuario, correo_electronico], (err, results) => {
    if (err) {
      console.error('Error al verificar si el usuario ya existe:', err);
      return res.status(500).json({ message: 'Error al verificar el usuario.' });
    }

    if (results.length > 0) {
      return res.status(400).json({ message: 'El nombre de usuario o correo ya está registrado.' });
    }

    // Hashear la contraseña
    bcrypt.hash(contrasena, 10, (errHash, contrasenaHasheada) => {
      if (errHash) {
        console.error('Error al hashear la contraseña:', errHash);
        return res.status(500).json({ message: 'Error al hashear la contraseña.' });
      }

      // Insertar el nuevo usuario en la base de datos
      const insertQuery = `
        INSERT INTO Usuarios (nombre_usuario, correo_electronico, contrasena_hashed)
        VALUES (?, ?, ?)
      `;

      db.query(insertQuery, [nombre_usuario, correo_electronico, contrasenaHasheada], (err2) => {
        if (err2) {
          console.error('Error al registrar usuario:', err2);
          return res.status(500).json({ message: 'Error al registrar el usuario.' });
        }

        // Redirigir a la ruta principal ("/") luego de registro exitoso
        return res.redirect('/');
      });
    });
  });
});

// Ruta para manejar el POST de cambio de contraseña
app.post('/reset-password', (req, res) => {
  const { token, contrasena } = req.body;

  const findTokenQuery = 'SELECT * FROM PasswordResetTokens WHERE token = ? AND expiration_time > ?';
  db.query(findTokenQuery, [token, Date.now()], (err, results) => {
    if (err) {
      console.error('Error al verificar el token:', err);
      return res.status(500).json({ message: 'Error en el servidor' });
    }

    if (results.length === 0) {
      return res.status(400).json({ message: 'Token inválido o expirado.' });
    }

    const correo_electronico = results[0].correo_electronico;

    bcrypt.hash(contrasena, 10, (errHash, contrasenaHasheada) => {
      if (errHash) {
        console.error('Error al hashear la contraseña:', errHash);
        return res.status(500).json({ message: 'Error en el servidor' });
      }

      const updatePasswordQuery = 'UPDATE Usuarios SET contrasena_hashed = ? WHERE correo_electronico = ?';
      db.query(updatePasswordQuery, [contrasenaHasheada, correo_electronico], (err2) => {
        if (err2) {
          console.error('Error al actualizar la contraseña:', err2);
          return res.status(500).json({ message: 'Error en el servidor' });
        }

        res.redirect('/');
      });
    });
  });
});

// Ruta para manejar el inicio de sesión
app.post('/login', (req, res) => {
  const { id_usuario, id_rol, contrasena } = req.body;

  if (!id_usuario || !contrasena) {
    return res.status(400).json({ message: 'Se requieren id_usuario y contrasena.' });
  }

  // 1. Buscar al usuario
  const findUserQuery = 'SELECT * FROM Usuarios WHERE id_usuario = ?';
  db.query(findUserQuery, [id_usuario], (err, results) => {
    if (err) {
      console.error('Error en el servidor:', err);
      return res.status(500).json({ message: 'Error en el servidor' });
    }
    if (results.length === 0) {
      return res.status(401).json({ message: 'Usuario no encontrado.' });
    }

    const user = results[0];
    const userId = user.id_usuario;

    // 2. Verificar si está bloqueado en la BD
    if (user.bloqueado) {
      const bloqueadoHasta = blockedUntilMap[userId] || 0;
      const ahora = Date.now();

      if (ahora < bloqueadoHasta) {
        const faltanMs = bloqueadoHasta - ahora;
        const faltanSeg = Math.ceil(faltanMs / 1000);
        return res
          .status(403)
          .send(`Este usuario está bloqueado. Intenta de nuevo en ${faltanSeg} segundos.`);
      } else {
        blockedUntilMap[userId] = 0;
        const resetQuery = `
          UPDATE Usuarios
          SET bloqueado = FALSE, intentos_fallidos = 0
          WHERE id_usuario = ?
        `;
        db.query(resetQuery, [userId], (errReset) => {
          if (errReset) {
            console.error('Error al resetear estado de bloqueo:', errReset);
            return res.status(500).json({ message: 'Error en el servidor' });
          }
          user.bloqueado = 0;
          user.intentos_fallidos = 0;
        });
      }
    }

    bcrypt.compare(contrasena, user.contrasena_hashed, (errCompare, isMatch) => {
      if (errCompare) {
        console.error('Error al comparar contraseñas:', errCompare);
        return res.status(500).json({ message: 'Error en el servidor' });
      }

      if (!isMatch) {
        const nuevosIntentos = user.intentos_fallidos + 1;

        // Si llega a 3, bloquear
        if (nuevosIntentos >= 3) {
          const cincoMinutos = 5 * 60 * 1000;
          const desbloqueoEn = Date.now() + cincoMinutos;

          const lockQuery = `
            UPDATE Usuarios
            SET intentos_fallidos = ?, bloqueado = TRUE
            WHERE id_usuario = ?
          `;
          db.query(lockQuery, [nuevosIntentos, userId], (errLock) => {
            if (errLock) {
              console.error('Error al bloquear usuario:', errLock);
              return res.status(500).json({ message: 'Error en el servidor' });
            }
            blockedUntilMap[userId] = desbloqueoEn;

            return res.status(403).send(
              'Has alcanzado 3 intentos fallidos. ' +
              'Tu usuario se ha bloqueado por 5 minutos.'
            );
          });
        } else {
          const updateAttemptsQuery = `
            UPDATE Usuarios
            SET intentos_fallidos = ?
            WHERE id_usuario = ?
          `;
          db.query(updateAttemptsQuery, [nuevosIntentos, userId], (errUp) => {
            if (errUp) {
              console.error('Error al actualizar intentos_fallidos:', errUp);
              return res.status(500).json({ message: 'Error en el servidor' });
            }
            return res
              .status(401)
              .send(`Contraseña incorrecta. Intentos fallidos: ${nuevosIntentos}`);
          });
        }
      } else {
        const resetAttemptsQuery = `
          UPDATE Usuarios
          SET intentos_fallidos = 0, bloqueado = FALSE
          WHERE id_usuario = ?
        `;
        db.query(resetAttemptsQuery, [userId], (errReset) => {
          if (errReset) {
            console.error('Error al resetear intentos_fallidos:', errReset);
            return res.status(500).json({ message: 'Error en el servidor' });
          }

          req.session.user = {
            id_usuario: user.id_usuario,
            nombre_usuario: user.nombre_usuario,
            correo_electronico: user.correo_electronico,
            bloqueado: false,
            rol: id_rol
          };

          return res.redirect('/welcome');
        });
      }
    });
  });
});

app.post('/logout', (req, res) => {
  // Destruir la sesión del usuario
  req.session.destroy((err) => {
    if (err) {
      console.error('Error al destruir sesión:', err);
      return res.redirect('/');  // Redirigir al login si hay un error
    }
    res.redirect('/'); // Redirigir al login después de cerrar sesión
  });
});

app.post('/assign-roles', (req, res) => {
  // Verifica si el usuario está en sesión (opcional, si lo deseas)
  if (!req.session.user) {
    return res.redirect('/');
  }

  // Obtén los valores del formulario
  const { id_usuario, id_rol } = req.body;

  // Validar que ambos datos existan
  if (!id_usuario || !id_rol) {
    return res.status(400).send('Faltan datos: id_usuario o id_rol.');
  }

  // Inserta la relación en la tabla Usuarios_Roles
  const insertRelationQuery = `
    INSERT INTO Usuarios_Roles (id_usuario, id_rol)
    VALUES (?, ?)
  `;

  db.query(insertRelationQuery, [id_usuario, id_rol], (err, result) => {
    if (err) {
      // Maneja la excepción de llave primaria duplicada si ya existe esa relación
      if (err.code === 'ER_DUP_ENTRY') {
        return res.send('Este usuario ya tiene asignado ese rol.');
      }
      console.error('Error al asignar rol:', err);
      return res.status(500).send('Error en el servidor');
    }

    // Si todo funciona, redirige a la página de bienvenida o muestra un mensaje
    res.redirect('/welcome');
    // O bien: res.send('Rol asignado con éxito.');
  });
});

app.listen(PORT, () => {
  console.log(`Servidor iniciado en http://localhost:${PORT}`);
});

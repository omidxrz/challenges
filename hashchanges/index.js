const express = require('express');
const crypto = require('node:crypto');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const { Sequelize, DataTypes } = require('sequelize');
const xss = require('xss');

// Setup HTML sanitizer
function sanitizeInput(dirtyString) {
  const allowedTag = 'body';
  const allowedEvents = ['onhashchange'];
  const eventWhiteList = allowedEvents.reduce((acc, event) => {
      acc[event] = true;
      return acc;
  }, {});

  const sanitized = xss(dirtyString, {
      whiteList: {
          [allowedTag]: Object.keys(eventWhiteList)
      },
      onTagAttr: (tag, name, value, isWhiteAttr) => {
          if (eventWhiteList[name]) {
              return name + '="' + xss.escapeAttrValue(value) + '"';
          }
      },
      stripIgnoreTag: true, // Remove all tags that are not in the whitelist
      stripIgnoreTagBody: ['script'], // Remove contents of specified tags
  });

  return sanitized;
}

// Setup middleware
const app = express();
app.set('view engine', 'ejs');
app.use(express.json());
app.use(bodyParser.json());
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
// app.use(sanitizeInput);

// Setup session management
app.use(session({
  secret: crypto.randomUUID(),
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
  },
}));

// Connect & setup database
const sequelize = new Sequelize('test', 'root', 'example', {
  host: 'db',
  dialect: 'mysql',
});

sequelize.authenticate()
  .then(() => {
    console.log('Connection has been established successfully.');
  })
  .catch((error) => {
    console.error('Unable to connect to the database:', error);
  });

// Define User model
const User = sequelize.define('User', {
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  firstname: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  lastname: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  bio: {
    type: DataTypes.STRING,
    allowNull: true,
  },
}, {});

// User.sync({ force: true });
sequelize.sync();

// Routes
app.get('/', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    res.redirect('/login');
  }
});

app.get('/register', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    res.render('register');
  }
});

app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ username, email, password: hashedPassword });
    req.session.userId = newUser.id;
    req.session.username = newUser.username;
    res.redirect('/dashboard');
  } catch (error) {
    res.render("register", {msg: error.message})
  }
});

app.get('/login', (req, res) => {
  if (req.session.userId) {
    res.redirect('/dashboard');
  } else {
    res.render('login');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ where: { username } });
    if (!user) {
      return res.render("login", {msg:"User not found!"})
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.render("login", {msg:"Invalid password!"})
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    res.redirect('/dashboard');
  } catch (error) {
    return res.render("login",{ msg: error.message})
  }
});




app.get('/profile/:username', async (req, res) => {
  const username = req.params.username;
  if (req.session.userId) {
    try {
      const user = await User.findOne({ where: { username } });
      if (!user) {
        //return res.redirect('/dashboard');
        return res.render("profile",{ msg: "User not found!"})
      } else {
        const sanitizedInput = sanitizeInput(user.firstname);
         res.render('profile', {
          firstname: sanitizedInput,
          lastname: user.lastname,
          bio: user.bio,
          username: user.username,
        });
      }
      
    } catch (error) {
      return res.render("profile",{ msg: error.message})
      //res.status(500).json({ error: error.message });
    }
  } else {
    res.redirect('/login');
  }
});

app.get('/dashboard', (req, res) => {
  if (req.session.userId) {
    res.render('dashboard', { username: req.session.username });
  } else {
    res.redirect('/login');
  }
});

app.get('/editprofile', (req, res) => {
  if (req.session.userId) {
    res.render('editprofile', { username: req.session.username });
  } else {
    res.redirect('/login');
  }
});

app.post('/editprofile', async (req, res) => {
  const { firstname, lastname, bio } = req.body;
  if (!req.session.userId) {
    return res.render('login');
  }

  const userId = req.session.userId;
  try {
    const user = await User.findOne({ where: { id: userId } });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    await User.update({ firstname, lastname, bio }, { where: { id: userId } });
    res.render('editprofile', { msg: 'Profile updated successfully' });
  } catch (error) {
    res.render('editprofile', { msg: error.message });
  }
});

app.set('port', process.env.PORT || 3000);
app.listen(app.get('port'), () => {
  console.log(`Express App running at http://127.0.0.1:${app.get('port')}/`);
});

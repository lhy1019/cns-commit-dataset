const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const Sequelize = require('sequelize');
const bcrypt = require('bcrypt');
const app = express();

const sequelize = new Sequelize({
    dialect: 'sqlite',
    storage: 'database.sqlite'
});

const User = sequelize.define('User', {
    username: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true
    },
    password: {
        type: Sequelize.STRING,
        allowNull: false
    }
});

const Post = sequelize.define('Post', {
    title: {
        type: Sequelize.STRING,
        allowNull: false
    },
    content: {
        type: Sequelize.TEXT,
        allowNull: false
    },
    author: {
        type: Sequelize.INTEGER,
        allowNull: false
    }
});

sequelize.sync();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret-key', resave: false, saveUninitialized: false }));
app.set('view engine', 'ejs');

app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login', { error: null }));
app.get('/register', (req, res) => res.render('register', { error: null }));
app.get('/post/:id', (req, res) => {
    Post.findByPk(req.params.id).then(post => {
        if (!post) return res.redirect('/');
        res.render('post', { post });
    }).catch(err => res.redirect('/'));
});
app.get('/newpost', (req, res) => res.render('newpost'));

app.get('/dashboard', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    Post.findAll({ where: { author: req.session.userId } }).then(posts => {
        res.render('dashboard', { posts });
    }).catch(err => res.redirect('/'));
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.render('register', { error: 'Username and password are required' });
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.render('register', { error: 'Error creating account' });
        User.create({ username, password: hash })
            .then(() => res.redirect('/login'))
            .catch(() => res.render('register', { error: 'Username already taken' }));
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.render('login', { error: 'Username and password are required' });
    }

    User.findOne({ where: { username } })
        .then(user => {
            if (!user) return res.render('login', { error: 'Invalid username or password' });

            bcrypt.compare(password, user.password, (err, result) => {
                if (result) {
                    req.session.userId = user.id;
                    res.redirect('/dashboard');
                } else {
                    res.render('login', { error: 'Invalid username or password' });
                }
            });
        })
        .catch(() => res.render('login', { error: 'Invalid username or password' }));
});

app.post('/newpost', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    Post.create({ title: req.body.title, content: req.body.content, author: req.session.userId })
        .then(() => res.redirect('/dashboard'))
        .catch(() => res.redirect('/newpost'));
});

app.listen(3000, () => console.log('Server started on http://localhost:3000'));

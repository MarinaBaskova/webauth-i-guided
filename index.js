const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // add bcryptjs

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
	res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
	let user = req.body;
	// check if you have username and password in the body

	// hash the password
	// use syncr cuz we need to wait for hash
	const hash = bcrypt.hashSync(user.password, 10); // pass the number - num will be num of rounds it will be hashed -> 2^10 rounds
	// pass > hashit > hash -- that it 1 round  .. hashit > hash > hashit > hash ..

	user.password = hash;
	// before adding the user hash the pasword
	Users.add(user)
		.then((saved) => {
			res.status(201).json(saved);
		})
		.catch((error) => {
			res.status(500).json(error);
		});
});

server.post('/api/login', (req, res) => {
	console.log('LOGIN', req.body);
	let { username, password } = req.body;
	console.log({ username });
	// we compare the pass guess against the DB hash
	Users.findBy({ username })
		.first()
		.then((user) => {
			// check here if we have user and we found it
			if (user && bcrypt.compareSync(password, user.password)) {
				res.status(200).json({ message: `Welcome ${user.username}!` });
			} else {
				res.status(401).json({ message: 'Invalid Credentials' });
			}
		})
		.catch((error) => {
			res.status(500).json(error);
		});
});

// protect this route, users must provide valid credentials to see the list of the users
server.get('/api/users', protected, (req, res) => {
	Users.find()
		.then((users) => {
			res.json(users);
		})
		.catch((err) => res.send(err));
});

// mw for protec the route

function protected(req, res, next) {
	const { username, password } = req.headers; // because server.GET('/api/users', (req, res) =>
	if (username && password) {
		// check the password
		Users.findBy({ username })
			.first()
			.then((user) => {
				// check here if we have user and we found it
				if (user && bcrypt.compareSync(password, user.password)) {
					next(); // call next after it found it and compared
				} else {
					res.status(401).json({ message: 'Invalid Credentials' });
				}
			})
			.catch((error) => {
				res.status(500).json(error);
			});
	} else {
		res.status(400).json({ message: 'Please provide credentials' });
	}
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));

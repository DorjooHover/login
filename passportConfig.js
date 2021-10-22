const LocalStrategy = require('passport-local')
const { pool } = require('./dbConfig')
const bcrypt = require('bcrypt')
const { authenticate } = require('passport')


function initialize(passport) {

    const authenticate = (email, password, done) => {
        pool.query(
            `select * from users where email = $1`, [email], (err, results) => {
                if (err) {
                    throw err;
                }

                if (results.rows.length > 0) {
                    const user = results.rows[0]

                    bcrypt.compare(password, user.password, (err, isMatch) => {
                        if (err) {
                            throw err;
                        }
                        if (isMatch) {
                            return done(null, user)
                        } else {
                            return done(null, false, { message: "Password is not correct" })
                        }
                    })
                } else {
                    return done(null, false, { message: 'Email is not registered' })
                }
            }
        )
    }
    passport.use(new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
    }, authenticate))

    passport.serializeUser((user, done) => done(null, user.id))

    passport.deserializeUser((id, done) => {
        pool.query(
            `select * from users where id=$1`, [id], (err, results) => {
                if (err) {
                    throw err
                }
                return done(null, results.rows[0])
            }
        )
    })
}

module.exports = initialize
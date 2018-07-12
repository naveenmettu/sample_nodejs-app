const request = require('supertest')
const assert = require('chai').assert
const sinon = require('sinon')

const EventEmitter = require('events')
const passport = require('passport')
const ldap = require('ldapjs');

describe('Test routes', () => {
  let server
  let ldapStub
  let ldapSearch
  before(() => {
    server = require('../../bin/www').server

    ldapStub = sinon.stub(ldap, 'createClient')
    ldapStub.callsFake((params) => {
      return {
        bind: function(dn, password, callback) {
          callback(null)
        },
        unbind: function() {},
        search: function(searchBase, options, callback) {
          ldapSearch = new EventEmitter()
          callback(null, ldapSearch)
        }
      }
    })

  })
  after(() => {
    server.close()
  })

  it('should redirect on / when unauthenticated', done => {
    request(server)
      .get('/')
      .expect(302)
      .end((err, res) => {
        assert(!err)
        done()
      })
  })

  it('should authenticate when requested', done => {
    setTimeout(() => {
      ldapSearch.emit('searchEntry', {
        raw: {
          dn: 'foobar',
          userPrincipalName: 'Foo Bar'
        }
      })
      ldapSearch.emit('end')
    }, 10)
    request(server)
      .post('/auth/login')
      .send('username=foobar&password=mypassword&requestSSO=')
      .expect(302)
      .end((err, res) => {
        assert(!err)
        done()
      })
  })

  it('should respond with username when authenticated', done => {
    const stub = sinon.stub(passport, 'authenticate')
    stub.callsFake((strategy, options) => {
      return (req, res, next) => {
        req.user = { id: 'foobar' }
        next()
      }
    })
    request(server)
      .get('/')
      .expect(200, done)
  })
})

const request = require('supertest')
const assert = require('chai').assert
const sinon = require('sinon')
const passport = require('passport')

describe('Test routes', () => {
  let server
  before(() => {
    server = require('../../bin/www').server
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

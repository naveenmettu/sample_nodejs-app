const request = require('supertest')
const assert = require('chai').assert

describe('Test routes', () => {
  let server
  before(() => {
    server = require('../../bin/www').server
  })
  after(() => {
    server.close()
  })

  it('Test route / - unauthenticated', done => {
    request(server)
      .get('/')
      .expect(302)
      .end((err, res) => {
        assert(!err)
        done()
      })
  })
})

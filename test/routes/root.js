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
      console.log('here')
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

  it('should process a SAML request', done => {
    // SAML request:
    // <?xml version="1.0"?><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_afba590baaf5b8e33472" Version="2.0" IssueInstant="2018-07-10T19:09:15.544Z" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="http://localhost:1337/login/callback" Destination="http://localhost:8080/idp/sso"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sample-sp/sp</saml:Issuer><samlp:NameIDPolicy xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/><samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Comparison="exact"><saml:AuthnContextClassRef xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></samlp:RequestedAuthnContext></samlp:AuthnRequest>
    const samlRequest = 'SAMLRequest=nVPBjtowEP2VyPcQZwEBFmFFQVWRtm0EaQ%2B9VBNnWKw6dupxdunf1wSyQmqXAyfLM2%2FePL8Zzx%2BPtY5e0JGyJmPpgLPHxZyg1o1Ytv5gtvi7RfJRgBkSXSJjrTPCAikSBmok4aXYLT8%2FiYcBF42z3kqrWbRZZ%2Bwn7EsYz3gJsB%2BXUxwOR5MHFn3vG4aKACRqcWPIg%2FEhxNNpzCdxyot0JvhMpOPBeDT6waL8Qv1BmUqZ59s6yjOIxKeiyOP8665g0ZIInQ%2BNV9ZQW6PboXtREr9tnzJ28L4RSaKtBH2w5EU6HE7C9VmZJIR0CfIXi9bBDGXAd%2Br%2FKZnyKU9U1SRElp19FN3r3JWBt3VDr5EtTvQU%2BENRozGmQNvMkyvSflJfAstmnVut5J97JvXRuhr8%2B%2Bh0kHYRVcX7DiqwBqWXVeWQKPiqtX1dOQSPGfOuRZb00i77g1W3TcF3j8e7tmll6wacopPveATpe3%2BviVc62LfF%2FT1u34RJIU%2FUIZyH49W66rSMKMPDCgeGGuv8ZTT%2F07M4596x4y17%2FeMWfwE%3D'

    request(server)
      .get('/idp/sso')
      .send(samlRequest)
      .expect(200, done)
  })
})

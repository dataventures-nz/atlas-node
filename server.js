const express = require('express');
const app = express();
const cors = require('cors');
const checkJwt = require('./checkJWT').checkJwt;
require('dotenv').config();
const bodyParser = require('body-parser');
const LISTEN_PORT = require('./config.js').LISTEN_PORT;
const MONGO_URI = require('./config.js').MONGO_URI;
const DB_NAME = require('./config.js').DB_NAME;
const MongoClient = require('mongodb').MongoClient;
const logger = require('morgan');
const fastCsv = require('fast-csv');
const moment = require('moment');

const corsOptions = {}; // everything for everyone

let client = new MongoClient(MONGO_URI, { poolSize:10, useNewUrlParser: true, useUnifiedTopology:true });
client.connect();

app.use(cors(corsOptions));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// deepmap is total overkill here, but I may end up using it in other places.
function deepMap(value, mapFn, thisArg, key, cache=new Map()) {
  // Use cached value, if present:
  if (cache.has(value)) {
    return cache.get(value)
  }
  if (Array.isArray(value)) { // for arrays
    let result = []
    cache.set(value, result) // Cache to avoid circular references
    for (let i = 0; i < value.length; i++) {
      result.push(deepMap(value[i], mapFn, thisArg, i, cache))
    }
    return result
  } else if (value != null && /object|function/.test(typeof value)) { // non array
    let result = {}
    cache.set(value, result) // Cache to avoid circular references
    for (let key of Object.keys(value)) {
      if (key in ['$merge','$out','$planCacheStats','$listSessions','$listLocalSessions','$graphLookup','$lookup','$collStats']) {
        throw 'some pipeline stages are not supported (anything which lets you look up other records), contact Data Ventures if you need to do this'
      }
      result[key] = deepMap(value[key], mapFn, thisArg, key, cache)
    }
    return result
  } else { // If value is a primitive:
    return mapFn.call(thisArg, value, key)
  }
}

function formatter(doc) {
  for (let i of Object.keys(doc)) {
    if (doc[i] instanceof Date) {
      doc[i] =  moment(doc[i]).format('YYYY-MM-DD HH:mm:ss')
    }
  }
  delete doc['_id']
  return doc
}

function maybeDate(node) {
  if ((node.startsWith && node.endsWith) && node.startsWith('#') && node.endsWith('#')) {
    return new Date(node.replace(/#/g,''))
  } else {
    return node
  }
}

async function makeQuery(req) {
  let table = req.params['table']
  let permissions = req.user.permissions
  console.log(permissions)
  let packages = permissions
    .filter(permission => permission.startsWith('api:'))
    .map(permission => permission.replace('api:',''))
  if (packages.length === 0) { packages = ['anonymous'] }

  const security_query = {
      'table': table,
      'package':{ '$in':packages }
  }

  console.log(security_query)
  const security_cursor = client.db(DB_NAME).collection('security').find(security_query)

  const security = await security_cursor.toArray();

  if (security.length===0) {
    throw "you don't have access to this table"
  }

  console.log("sec",security)
  let matches = security.map(sec => deepMap(JSON.parse(sec.pre),maybeDate))
  let limits = security.map(sec => sec.limit)
  let limit = Math.max(...limits)

  if (!req.body ) {
    req.body = []
  }

  let query = deepMap(req.body, maybeDate) // dates changed to local
//  query = deepMap(query, protect) // modify the query so you can't breach security
  if (query instanceof Array) {
    return [
      {$match:{
        $or:matches
      }},...query,
      {$limit:limit}
    ]
  } else {
    return [
      {$match:{
        $or:matches,
      }},
      {$match:query},
      {$limit:limit}
    ]
  }
}

app.get('/subscription/:table', checkJwt, async function(req, res) {
  let permissions = req.user.permissions
  let table = req.params['table']
  let packages = permissions
    .filter(permission => permission.startsWith('api:'))
    .map(permission => permission.replace('api:',''))
  if (packages.length === 0) { packages = ['anonymous'] }
  const security_query = {
      'table': table,
      'package':{ '$in':packages }
  }
  console.log(security_query)
  const security_cursor = client.db(DB_NAME).collection('security').find(security_query)
  res.writeHead(200, { 'Content-Type': 'text/csv' })
  res.flushHeaders()
  const csvStream = fastCsv.format({ headers: true }).transform(formatter)
  security_cursor.stream().pipe(csvStream).pipe(res)
})

async function doQuery(req,res) {
  let q = makeQuery(req)
    q.catch(err => res.status(500).json({ message: err }))
    q.then(function(query,fail) {
      console.log(query, JSON.stringify(query))
      let table = req.params['table']
      let cursor = client.db(DB_NAME).collection(table).aggregate(query)
      res.setHeader('Content-disposition', 'attachment filename=stuff.csv')
      res.writeHead(200, { 'Content-Type': 'text/csv' })
      res.flushHeaders()
      const csvStream = fastCsv.format({ headers: true }).transform(formatter)
      cursor.stream().pipe(csvStream).pipe(res)
    })
}


app.post('/api/:table', checkJwt, doQuery)
app.get('/api/:table', checkJwt, doQuery)

app.get('/health', (req,res) => res.send("ok - version 1.14"))

app.get('/meta/:api', checkJwt, async function(req, res) {
  let permissions = req.user.permissions
  let table = req.params['table']
  let packages = permissions
    .filter(permission => permission.startsWith('api:'))
    .map(permission => permission.replace('api:',''))
  if (packages.length === 0) { packages = ['anonymous'] }
  const meta_query = {
      'api': api,
      'package':{ '$in':packages }
  }
  console.log(meta_query)
  const meta_cursor = client.db(DB_NAME).collection('meta').find(meta_query)
  const meta = await meta_cursor.toArray();

  if (meta.length===0) {
    meta = [{api, defaulting:true, collection:api}]
  }

  res.writeHead(200, { 'Content-Type': 'text/csv' })
  res.flushHeaders()
  const csvStream = fastCsv.format({ headers: true }).transform(formatter)
  csvStream.pipe(res)
  csvStream.write(meta[0])
  csvStream.end()
})

app.use(function(err, req, res, next) {
  console.error(err.stack)
  return res.status(err.status).json({ message: err.message })
})

app.listen(LISTEN_PORT)
console.log('Listening on http://localhost:' + LISTEN_PORT)

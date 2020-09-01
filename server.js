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
const Stream = require('stream')
const mongoSafe = require('./mongosafe.js').isSafe
const compression = require('compression');

// This is a service, so, everything for everyone
// it is meant to be public on the net, and hopefully intergrated into peoples
// own applications.
// for security, the calls to it contain JWT
const corsOptions = {};

let client = new MongoClient(MONGO_URI, { poolSize:10, useNewUrlParser: true, useUnifiedTopology:true });
client.connect();

// app.use(compression({ threshold: 0 }))
app.use(cors(corsOptions));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// deepMap is used for 2 things, firstly, we intergrated query sanitisation.
// yeah, I know, black lists on keys is not ideal, but, there is very little
// we don't want the user doing. no adding records, no linking back to self or to other tables.
// we also block some informational requests which people shouldn't have any reason to use.
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
      if (!mongoSafe(key)) {
        throw 'some pipeline stages are not supported (anything which lets you look up other records), contact Data Ventures if you need to do this'
      }
      result[key] = deepMap(value[key], mapFn, thisArg, key, cache)
    }
    return result
  } else { // If value is a primitive:
    return mapFn.call(thisArg, value, key)
  }
}

// We check the JWT token here. This is a slight modification so we can flag
// some 'users' as automationed processes which should last forever.
// there is a EXTREMELY tiny amount of keys like this (currently 1)
// and we can change the permission to invalidate it.
// security, it is about tradeoffs sometimes.
function checkTime(req, res, next) {
  var clockTimestamp = Math.floor(Date.now() / 1000)
  var exp = req.user.exp
  if (!req.user.permissions.includes("api:forever")) {
    if (clockTimestamp >= exp) {
      throw new TokenExpiredError('maxAge exceeded', new Date(maxAgeTimestamp * 1000))
    }
  } else {
    console.log("WARNING - token never expires")
  }
  next()
}

// in THEORY, we will get getting the format from the user record at some point.
// in practice, they will get a sensible format, and they will like it.
// we MAY add timezone support in the future, to a limited degree.
// and when that day happens, this will be updated.
function formatter(doc) {
  for (let i of Object.keys(doc)) {
    if (doc[i] instanceof Date) {
      doc[i] =  moment(doc[i]).format('YYYY-MM-DD HH:mm:ss')
    }
  }
  delete doc['_id']
  return doc
}

// we need a way to flag something as a date, since, json doesn't do dates.
// 2012-01-01 is a string. #2012-01-01# is a date.
// it isn't following a standard, but that is because there isn't a standard to follow.
function maybeDate(node) {
  if ((node.startsWith && node.endsWith) && node.startsWith('#') && node.endsWith('#')) {
    return new Date(node.replace(/#/g,''))
  } else {
    return node
  }
}

// users CAN have a lot of permissions NOT applicable to the API.
// so we filter them out before we do any more processing.
// it helps reducing noise in logging, among other things.
function getPackages(req) {
  let permissions = req.user.permissions
  console.log(permissions)
  let packages = permissions
    .filter(permission => permission.startsWith('api:'))
    .map(permission => permission.replace('api:',''))
  if (packages.length === 0) { packages = ['anonymous'] }
  return packages
}

// ok, here is the meaty inside here.
// we turn their queries into pipline queries if they are not already.
// we apply the security model to the start of the query.
// we check to see what the max size of the query can return (honestly, we could remove this)
//
async function makeQuery(req) {
  let table = req.params['table']
  const packages = getPackages(req)
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

  // dates are checked and parsed, AND bad keys removed - this is where we sanitise the query.
  let query = deepMap(req.body, maybeDate)

  // if you were not a pipeline query already, you are now.
  if (query instanceof Array) {
    return [
      {$match:{
        $or:matches
      }},...query
    ]
  } else {
    return [
      {$match:{
        $or:matches,
      }},
      {$match:query}
    ]
  }
}

app.get('/subscription/:table', checkJwt, checkTime, async function(req, res) {
  const packages = getPackages(req)
  let table = req.params['table']
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

app.get('/subscription', checkJwt, checkTime, async function(req, res) {
  const packages = getPackages(req)
  let table = req.params['table']
  const security_query = {
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
  let table = req.params['table']
  const meta = await getMeta(getPackages(req), table)
  console.log("meta is ", meta)
  // TODO: if there is more than one meta, push a log to the admin system saying that we screwed up metadata selectors.
  // it doesn't give people access to stuff they shouldn't have, but, it is bad since they may get the wrong version of data.
  // worse yet, it MAY be random.... *gasp*
  let q = makeQuery(req)
    q.catch(err => res.status(500).json({ message: err }))
    q.then(function(query,fail) {
      console.log(query, JSON.stringify(query))
      let cursor = client.db(DB_NAME).collection(meta[0].collection).aggregate(query)
      res.setHeader('Content-disposition', 'attachment filename=stuff.csv')
      res.writeHead(200, { 'Content-Type': 'text/csv' })
      res.flushHeaders()
      const csvStream = fastCsv.format({ headers: true }).transform(formatter)
      cursor.stream().pipe(csvStream).pipe(res)
    })
}

async function doCount(req,res) {
  let table = req.params['table']
  const meta = await getMeta(getPackages(req), table)
  let count = await client.db(DB_NAME).collection(meta[0].collection).estimatedDocumentCount() 
  res.json({count})
}

app.post('/api/:table', checkJwt, checkTime, doQuery)
app.get('/api/:table', checkJwt, checkTime, doQuery)
app.get('/count/:table', checkJwt, checkTime, doCount)

app.get('/health', (req,res) => res.send("ok - version 1.34 (no compression)\n"))

// note.... THIS has to be fast. since we use it as part of the regular query system.
// so it will only do one call, and not add a bunch of extra stuff to it.
async function getMeta(packages, api) {
  const meta_query = {
      'api': api,
      'package':{ '$in':packages }
  }
  const meta_cursor = client.db(DB_NAME).collection('meta').find(meta_query)
  let meta = await meta_cursor.toArray()
  if (meta.length===0) {
    meta = [{api, defaulting:true, collection:api}]
  }
  return meta
}

async function getFieldsFor(table) {
  const fields_query = [
    {
      '$limit': 1000
    }, {
      '$project': {
        'fields': {
          '$objectToArray': '$$ROOT'
        }
      }
    }, {
      '$unwind': '$fields'
    }, {
      '$project': {
        'fields': {
          'k': '$fields.k', 
          'v': {
            '$type': '$fields.v'
          }
        }
      }
    }, {
      '$group': {
        '_id': '$fields.k', 
        'fields': {
          '$addToSet': '$fields.v'
        }
      }
    }
  ]

  const fields_cursor = client.db(DB_NAME).collection(table).aggregate(fields_query)
  let result = {}
  let fields = await fields_cursor.toArray()
  fields.map(r => {result[r._id] = r.fields})
  return result
}


// and CAN be slower, so we can do extra querys here, and will do so.
app.get('/meta/:api', checkJwt, checkTime, async function(req, res) {
  let permissions = req.user.permissions
  let api = req.params['api']
  let packages = permissions
    .filter(permission => permission.startsWith('api:'))
    .map(permission => permission.replace('api:',''))
  if (packages.length === 0) { packages = ['anonymous'] }
  let meta = await getMeta(packages,api)
  console.log("meta for ", packages, api, meta)
  let fields = await getFieldsFor(meta[0].collection)
  meta[0].fields = fields
  console.log("fields for :", meta[0].collection, " = ", fields)
  res.json(meta[0])
})

// error messages.
app.use(function(err, req, res, next) {
  console.error(err.stack)
  return res.status(err.status).json({ message: err.message })
})

app.listen(LISTEN_PORT)
console.log('Listening on http://localhost:' + LISTEN_PORT)

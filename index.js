// based on @ericvicenti's approach for ssh-keygen


var spawn = require('child_process').spawn
  , _     = require('underscore')
  , fs    = require('fs')
  , os    = require('os')
  , path  = require('path')
  , util  = require('util')
  ;


exports.x509_keygen = function(options, callback) {
  options = options || {};
  if (_.isUndefined(options.read))    options.read    = true;
  if (_.isUndefined(options.force))   options.force   = true;
  if (_.isUndefined(options.destroy)) options.destroy = true;
  if (_.isUndefined(options.logger)) {
    options.logger = { error   : function(msg, props) { console.log(msg); if (!!props) console.trace(props.exception); }
                     , warning : function(msg, props) { console.log(msg); if (!!props) console.log(props);             }
                     , notice  : function(msg, props) { console.log(msg); if (!!props) console.log(props);             }
                     , info    : function(msg, props) { console.log(msg); if (!!props) console.log(props);             }
                     , debug   : function(msg, props) { console.log(msg); if (!!props) console.log(props);             }
                     };
  }

  if (_.isUndefined(options.subject)) return callback(new Error('options must include subject'));

  options.location = options.location || path.join(os.tmpDir(), 'server_rsa');
  options.keyfile  = options.keyfile  || options.location + '.key';
  options.certfile = options.certfile || options.location + '.cert';
  options.sha1file = options.sha1file || options.location + '.sha1';

  fs.exists(options.keyfile, function(keyP) {
    if ((!options.force) && keyP)    return callback(new Error(options.keyfile  + ' already exists'));

    fs.exists(options.certfile, function(certP) {
      if ((!options.force) && certP) return callback(new Error(options.certfile + ' already exists'));

      if ((!keyP) && (!certP)) return middle(options, callback);

      if (keyP) {
        fs.unlink(options.keyfile, function(err) {
          if (err) return callback(err);
          keyP = false;

          if ((!keyP) && (!certP)) return middle(options, callback);
        });
      }

      if (certP) {
        fs.unlink(options.certfile, function(err) {
          if (err) return callback(err);
          certP = false;

          if ((!keyP) && (!certP)) return middle(options, callback);
        });
      }
    });
  });
};

var middle = function(options, callback) {
  var config, i, ifaddrs, iface, ifaces, hostname, s;

  if (!!options.configfile) return inner(options, callback);

  if (!options.alternates || !util.isArray(options.alternates)) {
    options.alternates =  [ 'DNS:localhost' ];
    hostname = os.hostname();
    options.alternates.push('DNS:' + ((hostname.indexOf('.') != -1) ? hostname : (hostname + '.local')));
    
    ifaces = os.networkInterfaces();
    for (iface in ifaces) if (ifaces.hasOwnProperty(iface)) {
      ifaddrs = ifaces[iface];
      for (i = 0; i < ifaddrs.length; i++) if (ifaddrs[i].family === 'IPv4') options.alternates.push('IP:'+ifaddrs[i].address);
    }
  }
  config = '[ req ]\ndistinguished_name = dn_req\nx509_extensions = v3_req\n\n[ dn_req ]\n\n[ v3_req ]\n';
  config += 'basicConstraints=CA:TRUE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n';
  if (options.alternates.length > 0) {
    config += 'subjectAltName="';
    for (i = 0, s = ''; i < options.alternates.length; i++, s = ',') config += s + options.alternates[i];
    config += '"\n';
  }

  options.configfile = options.location + '.conf';
  fs.writeFile (options.configfile, config, { mode: 0644 }, function(err) {
    if (err) return callback(err);

    inner(options, function(err, results) {
      fs.unlink(options.configfile);
      callback(err, results);
    });
  });
};

var inner = function(options, callback) {
  var args, keygen;

  args =  [ 'req',     '-x509'
          , '-newkey', 'rsa:2048'
          , '-days',   '3650'
          , '-nodes'
          , '-subj',   options.subject
          , '-keyout', options.keyfile
          , '-out',    options.certfile
          ];
  if (!!options.configfile) args.push('-config', options.configfile);

  keygen = spawn('openssl', args);

  keygen.stdout.on('data', function(a){
    options.logger.info(a);
  });
  keygen.stderr.on('data',function(a){
    options.logger.debug('openssl: ' + a);
  });

  keygen.on('exit', function() {
    var readcert = function(key, sha1, der) {
      fs.readFile(options.certfile, 'utf8', function(err, cert) {
        if (!options.destroy) return callback(null, { key: key, cert: cert, sha1: sha1, der: der });

        fs.unlink(options.certfile, function(err){
          if (err) return callback(err);

          return callback(null, { key: key, cert: cert, sha1: sha1, der: der });
        });
      });
    };

    var makeder = function(key, sha1) {
      var hashgen, der;

      if (!options.derfile) return readcert(key, sha1);

      hashgen = spawn('openssl', [ 'x509', '-inform', 'pem', '-outform', 'der', '-in', options.certfile ]);
      der = null;
      hashgen.stdout.on('data', function(data) { der = der ? Buffer.concat(der, data) : data; });
      hashgen.stderr.on('data',function(a){
        options.logger.debug('openssl: ' + a);
      });
      hashgen.on('exit', function() {
        if (options.destroy) return readcert(key, sha1, der);

        fs.unlink(options.derfile, function(err) {
          if ((!!err) && (err.code !== 'ENOENT')) return callback(err);

          fs.writeFile (options.derfile, der, { mode: 0444 }, function(err) {
            if (err) return callback(err);

            readcert(key, sha1, der);
          });
        });
      });
    };

    var makesha1 = function(key) {
      var hashgen, sha1;

      hashgen = spawn('openssl', [ 'x509', '-sha1', '-in', options.certfile, '-noout', '-fingerprint' ]);
      sha1 = '';
      hashgen.stdout.on('data', function(data) { sha1 += data.toString(); });
      hashgen.stderr.on('data',function(a){
        options.logger.debug('openssl: ' + a);
      });
      hashgen.on('exit', function() {
        if (options.destroy) return makeder(key, sha1);

        fs.unlink(options.sha1file, function(err) {
          if ((!!err) && (err.code !== 'ENOENT')) return callback(err);

          fs.writeFile (options.sha1file, sha1, { mode: 0444 }, function(err) {
            if (err) return callback(err);

            makeder(key, sha1);
          });
        });
      });
    };

    if(!options.read) return callback(null, {});

    fs.readFile(options.keyfile, 'utf8', function(err, key) {
      if (!options.destroy) return makesha1(key);

      fs.unlink(options.keyfile, function(err){
        if (err) return callback(err);

        makesha1(key);
      });
    });
  });
};

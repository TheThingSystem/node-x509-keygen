// based on @ericvicenti's approach for ssh-keygen


var spawn = require('child_process').spawn
  , _     = require('underscore')
  , fs    = require('fs')
  , os    = require('os')
  , path  = require('path')
  ;


exports.x509_keygen = function(options, callback) {
  options = options || {};
  if (_.isUndefined(options.read))    options.read    = true;
  if (_.isUndefined(options.force))   options.force   = true;
  if (_.isUndefined(options.destroy)) options.destroy = true;
  if (_.isUndefined(options.logger)) {
    options.logger = { error   : function(msg, props) { console.log(msg); if (props) console.log(props.exception); }
                     , warning : function(msg, props) { console.log(msg); if (props) console.log(props);           }
                     , notice  : function(msg, props) { console.log(msg); if (props) console.log(props);           }
                     , info    : function(msg, props) { console.log(msg); if (props) console.log(props);           }
                     , debug   : function(msg, props) { console.log(msg); if (props) console.log(props);           }
                     };
  }

  if (_.isUndefined(options.subject)) return callback(new Error('options must include subject'));

  options.location = options.location || path.join(os.tmpDir(), 'server_rsa');
  options.keyfile  = options.location + '.key';
  options.certfile = options.location + '.cert';

  fs.exists(options.keyfile, function(keyP) {
    if ((!options.force) && keyP)    return callback(new Error(options.keyfile  + ' already exists'));

    fs.exists(options.certfile, function(certP) {
      if ((!options.force) && certP) return callback(new Error(options.certfile + ' already exists'));

      if ((!keyP) && (!certP)) return inner(options, callback);

      if (keyP) {
        fs.unlink(options.keyfile, function(err) {
          if (err) return callback(err);
          keyP = false;

          if ((!keyP) && (!certP)) return inner(options, callback);
        });
      }

      if (certP) {
        fs.unlink(options.certfile, function(err) {
          if (err) return callback(err);
            certP = false;

            if ((!keyP) && (!certP)) return inner(options, callback);
        });
      }
    });
  });
};

var inner = function(options, callback) {
  var args  =  [ 'req',     '-x509'
               , '-newkey', 'rsa:2048'
               , '-days',   '3650'
               , '-nodes'
               , '-subj',   options.subject
               , '-keyout', options.keyfile
               , '-out',    options.certfile
               ]
    , keygen = spawn('openssl', args)
   ;

  keygen.stdout.on('data', function(a){
    options.logger.info(a);
  });
  keygen.stderr.on('data',function(a){
    options.logger.error('openssl: ' + a);
  });

  keygen.on('exit', function() {
    var readcert = function(key) {
      fs.readFile(options.certfile, 'utf8', function(err, cert) {
        if (!options.destroy) return callback(null, { key: key, cert: cert });

        fs.unlink(options.certfile, function(err){
          if(err) return callback(err);

           return callback(null, { key: key, cert: cert });
        });
      });
    };

    if(!options.read) return callback(null, {});

    fs.readFile(options.keyfile, 'utf8', function(err, key) {
      if (!options.destroy) return readcert(key);

      fs.unlink(options.keyfile, function(err){
        if(err) return callback(err);

        readcert(key);
      });
    });
  });
};

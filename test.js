var keygen = require('./x509-keygen').x509_keygen;

keygen({ subject: '/CN=subject' }, function(err, data) {
  if (err) { console.log('error'); console.log(err); }

  console.log(data.key);
  console.log(data.cert);
  console.log(data.hash);
});

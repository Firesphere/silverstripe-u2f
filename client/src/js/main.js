require('google-u2f-api.js/u2f-api');

const handleAuthentication = (data) => {
  const xhttp = new XMLHttpRequest();
  const postData = new FormData();
  xhttp.onreadystatechange = function() {
    if (this.readyState === 4 && this.status === 201) {
      const response = JSON.parse(this.response);
      if (response.success) {
        alert ('You have successfully registered your U2F key');
      }
      return response;

    }
  };
  postData.append('registration', JSON.stringify(data));
  xhttp.open('POST', 'https://192.168.33.5/u2f/register', true);
  xhttp.send(postData);
};

const handleSign = (data) => {
  const xhttp = new XMLHttpRequest();
  const postData = new FormData();
  xhttp.onreadystatechange = function() {
    if (this.readyState === 4 && this.status === 200) {
      const response = JSON.parse(this.response);
      if (response.success) {
        alert ('You are successfully authenticated!')
      }
      return response;
    }
  };
  postData.append('authentication', JSON.stringify(data));
  xhttp.open('POST', 'https://192.168.33.5/u2f/authenticate', true);
  xhttp.send(postData);

};

const init = () => {
  const xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState === 4 && this.status === 200) {
      const response = JSON.parse(this.response);
      const req = response.registerRequests[0];
      const sigs = response.registeredKeys;
      // If there's no signature, it's definitely a need for registration
      if (sigs.length === 0) {
        const registerRequests = [{version: req.version, challenge: req.challenge, attestation: 'direct'}];
        u2f.register(sigs, registerRequests, [], (data) => {
          if(data.errorCode && data.errorCode !== 0) {
            alert("registration failed with errror: " + data.errorCode);
            return;
          }
          return handleAuthentication(data);
        });
      }
      // There's a signature, meaning we definitely are dealing with an authentication
      if (sigs.length > 0) {
            const signRequest = response.challenge;
            u2f.sign([], signRequest, sigs, (data) => {
              return handleSign(data);
            })
          }
      }
    };
  xhttp.overrideMimeType('application/json');
  xhttp.open("GET", "https://192.168.33.5/u2f/getdata", true);
  xhttp.send();
};

init();

export default init;

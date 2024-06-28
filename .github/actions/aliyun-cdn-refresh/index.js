const core = require('@actions/core');
const axios = require('axios');
const crypto = require('crypto');

async function run() {
    try {
        const accessKeyId = core.getInput('accessKeyId');
        const accessKeySecret = core.getInput('accessKeySecret');
        const type = core.getInput('type');
        const path = core.getInput('path');

        // Generate signature and make API request
        const timestamp = new Date().toISOString().replace(/[:\-]|\.\d{3}/g, '');
        const queryString = `AccessKeyId=${accessKeyId}&Action=RefreshObjectCaches&ObjectType=${type}&ObjectPath=${encodeURIComponent(path)}&Format=JSON&SignatureMethod=HMAC-SHA1&SignatureNonce=${crypto.randomBytes(16).toString('hex')}&SignatureVersion=1.0&Timestamp=${encodeURIComponent(timestamp)}&Version=2018-05-10`;

        const stringToSign = `GET&%2F&${encodeURIComponent(queryString)}`;
        const hmac = crypto.createHmac('sha1', accessKeySecret + '&');
        const signature = hmac.update(stringToSign).digest('base64');

        const url = `https://cdn.aliyuncs.com/?${queryString}&Signature=${encodeURIComponent(signature)}`;

        const response = await axios.get(url);
        console.log('Response:', response.data);

        if (response.data.Code && response.data.Code !== 'Success') {
            core.setFailed(`CDN refresh failed: ${response.data.Message}`);
        }
    } catch (error) {
        core.setFailed(`Action failed with error ${error}`);
    }
}

run();

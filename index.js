const execSync = require('child_process').execSync;
const homeDir = require('os').homedir();
const fs = require('fs');
const path = require('path');

function run(command) {
  console.log(command);
  execSync(command, {stdio: 'inherit'});
}

function getVersion() {
  let version = process.env['INPUT_ELASTICSEARCH-VERSION'] || '7';
  if (version == '7') {
    version = '7.10.0';
  } else if (version == '6') {
    version = '6.8.13';
  }

  if (!/^[67]\.\d{1,2}\.\d{1,2}$/.test(version)) {
    throw `Elasticsearch version not supported: ${version}`;
  }

  return version;
}

function isWindows() {
  return process.platform == 'win32';
}

// no JDK version is ideal, but deprecated
function getUrl() {
  let url;
  if (process.platform == 'darwin') {
    if (elasticsearchVersion[0] == '6') {
      url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}.tar.gz`;
    } else {
      url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}-darwin-x86_64.tar.gz`;
    }
  } else if (isWindows()) {
    if (elasticsearchVersion[0] == '6') {
      url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}.zip`;
    } else {
      url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}-windows-x86_64.zip`;
    }
  } else {
    if (elasticsearchVersion[0] == '6') {
      url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}.tar.gz`;
    } else {
      url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}-linux-x86_64.tar.gz`;
    }
  }
  return url;
}

function download() {
  const url = getUrl();
  if (isWindows()) {
    run(`curl -s -o elasticsearch.zip ${url}`);
    run(`unzip -q elasticsearch.zip`);
  } else {
    run(`wget -q -O elasticsearch.tar.gz ${url}`);
    run(`tar xfz elasticsearch.tar.gz`);
  }
  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, {recursive: true});
  }
  run(`mv elasticsearch-${elasticsearchVersion} ${esHome}`);
}

// TODO install all plugins with single command in Elasticsearch 7.10+
function installPlugins() {
  const plugins = (process.env['INPUT_PLUGINS'] || '').trim().split(/\s*[,\n]\s*/);
  if (plugins.length > 0) {
    console.log('Installing plugins');

    const pluginCmd = path.join(esHome, 'bin', 'elasticsearch-plugin');
    plugins.forEach( function(plugin) {
      if (!/^[a-zA-Z0-9-]+$/.test(plugin)) {
        throw `Invalid plugin: ${plugin}`;
      }
      run(`${pluginCmd} install --silent ${plugin}`);
    });
  }
}

function startServer() {
  if (isWindows()) {
    const serviceCmd = path.join(esHome, 'bin', 'elasticsearch-service');
    run(`${serviceCmd} install`);
    run(`${serviceCmd} start`);
  } else {
    run(`${path.join(esHome, 'bin', 'elasticsearch')} -d`);
  }
}

function waitForReady() {
  console.log("Waiting for server to be ready");
  for (let i = 0; i < 30; i++) {
    try {
      execSync(`curl -s localhost:9200`);
      break;
    } catch {
      execSync(`sleep 1`);
    }
  }
}

const elasticsearchVersion = getVersion();
const cacheDir = path.join(homeDir, 'elasticsearch');
const esHome = path.join(cacheDir, elasticsearchVersion);

if (!fs.existsSync(esHome)) {
  download();
  installPlugins();
} else {
  console.log('Elasticsearch cached');
}

startServer();

waitForReady();

// set ES_HOME
fs.appendFileSync(process.env.GITHUB_ENV, `ES_HOME=${esHome}`);

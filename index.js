const spawnSync = require('child_process').spawnSync;
const homeDir = require('os').homedir();
const fs = require('fs');
const path = require('path');

const versionMap = {
  '7': '7.10.0',
  '6': '6.8.13',
  '7.10': '7.10.0',
  '7.9': '7.9.3',
  '7.8': '7.8.1',
  '7.7': '7.7.1',
  '7.6': '7.6.2',
  '7.5': '7.5.2',
  '7.4': '7.4.2',
  '7.3': '7.3.2',
  '7.2': '7.2.1',
  '7.1': '7.1.1',
  '7.0': '7.0.1',
  '6.8': '6.8.13',
  '6.7': '6.7.2',
  '6.6': '6.6.2',
  '6.5': '6.5.4',
  '6.4': '6.4.3',
  '6.3': '6.3.2',
  '6.2': '6.2.4',
  '6.1': '6.1.4',
  '6.0': '6.0.1'
};

function run() {
  const args = Array.from(arguments);
  console.log(args.join(' '));
  const command = args.shift();
  const ret = spawnSync(command, args, {stdio: 'inherit'});
  if (ret.status !== 0) {
    throw ret.error;
  }
}

function getVersion() {
  let version = process.env['INPUT_ELASTICSEARCH-VERSION'] || '7';
  if (versionMap[version]) {
    version = versionMap[version];
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
    run('curl', '-s', '-o', 'elasticsearch.zip', url);
    run('unzip', '-q', 'elasticsearch.zip');
  } else {
    run('wget', '-q', '-O', 'elasticsearch.tar.gz', url);
    run('tar', 'xfz', 'elasticsearch.tar.gz');
  }
  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, {recursive: true});
  }
  fs.renameSync(`elasticsearch-${elasticsearchVersion}`, esHome);
}

function installPlugins() {
  const plugins = (process.env['INPUT_PLUGINS'] || '').trim().split(/\s*[,\n]\s*/);
  if (plugins.length > 0) {
    console.log('Installing plugins');

    // validate
    plugins.forEach( function(plugin) {
      if (!/^[a-zA-Z0-9-]+$/.test(plugin)) {
        throw `Invalid plugin: ${plugin}`;
      }
    });

    // install multiple plugins at once with Elasticsearch 7.6+
    // https://www.elastic.co/guide/en/elasticsearch/plugins/7.6/installing-multiple-plugins.html
    const versionParts = elasticsearchVersion.split('.');
    const atOnce = parseInt(versionParts[0]) >= 7 && parseInt(versionParts[1]) >= 6;
    const pluginCmd = path.join(esHome, 'bin', 'elasticsearch-plugin');
    if (atOnce) {
      run(pluginCmd, 'install', '--silent', ...plugins);
    } else {
      plugins.forEach( function(plugin) {
        run(pluginCmd, 'install', '--silent', plugin);
      });
    }
  }
}

function startServer() {
  if (isWindows()) {
    const serviceCmd = path.join(esHome, 'bin', 'elasticsearch-service');
    run(serviceCmd, 'install');
    run(serviceCmd, 'start');
  } else {
    run(path.join(esHome, 'bin', 'elasticsearch'), '-d', '-E', 'discovery.type=single-node');
  }
}

function waitForReady() {
  console.log("Waiting for server to be ready");
  for (let i = 0; i < 30; i++) {
    let ret = spawnSync('curl', ['-s', 'localhost:9200']);
    if (ret.status === 0) {
      break;
    }
    spawnSync('sleep', ['1']);
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

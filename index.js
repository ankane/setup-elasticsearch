const spawnSync = require('child_process').spawnSync;
const fs = require('fs');
const os = require('os');
const path = require('path');
const process = require('process');

const versionMap = {
  '9': '9.4.0',
  '8': '8.19.12',
  '9.4': '9.4.0',
  '9.3': '9.3.4',
  '9.2': '9.2.8',
  '9.1': '9.1.10',
  '9.0': '9.0.8',
  '8.19': '8.19.12',
  '8.18': '8.18.8',
  '8.17': '8.17.10',
  '8.16': '8.16.6',
  '8.15': '8.15.5',
  '8.14': '8.14.3',
  '8.13': '8.13.4',
  '8.12': '8.12.2',
  '8.11': '8.11.4',
  '8.10': '8.10.4',
  '8.9': '8.9.2',
  '8.8': '8.8.2',
  '8.7': '8.7.1',
  '8.6': '8.6.2',
  '8.5': '8.5.3',
  '8.4': '8.4.3',
  '8.3': '8.3.3',
  '8.2': '8.2.3',
  '8.1': '8.1.3',
  '8.0': '8.0.1'
};

const env = Object.assign({}, process.env);
delete env.JAVA_HOME;

function run() {
  const args = Array.from(arguments);
  console.log(args.join(' '));
  const command = args.shift();
  // spawn is safer and more lightweight than exec
  const ret = spawnSync(command, args, {stdio: 'inherit', env: env});
  if (ret.status !== 0) {
    throw ret.error;
  }
}

// only use with validated input
// https://github.com/nodejs/node/issues/52554
function runBat() {
  const args = Array.from(arguments);
  console.log(args.join(' '));
  const command = args.shift();
  if (!fs.existsSync(command)) {
    throw 'Bat not found';
  }
  const ret = spawnSync(command, args, {stdio: 'inherit', env: env, shell: true});
  if (ret.status !== 0) {
    throw ret.error;
  }
}

function addToEnv(value) {
  fs.appendFileSync(process.env.GITHUB_ENV, `${value}\n`);
}

function addToPath(value) {
  fs.appendFileSync(process.env.GITHUB_PATH, `${value}\n`);
}

function getVersion() {
  let version = process.env['INPUT_ELASTICSEARCH-VERSION'] || '9';
  if (versionMap[version]) {
    version = versionMap[version];
  }
  if (!/^[89]\.\d{1,2}\.\d{1,2}$/.test(version)) {
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
    if (process.arch == 'arm64') {
      url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}-darwin-aarch64.tar.gz`;
    } else {
      url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}-darwin-x86_64.tar.gz`;
    }
  } else if (isWindows()) {
    url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}-windows-x86_64.zip`;
  } else {
    if (process.arch == 'arm64') {
      url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}-linux-aarch64.tar.gz`;
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
  if (isWindows()) {
    // fix for: cross-device link not permitted
    run('mv', `elasticsearch-${elasticsearchVersion}`, esHome)
  } else {
    fs.renameSync(`elasticsearch-${elasticsearchVersion}`, esHome);
  }
}

function installPlugins() {
  let plugins = (process.env['INPUT_PLUGINS'] || '').trim();
  if (plugins.length > 0) {
    console.log('Installing plugins');

    // split here instead of above since JS returns [''] for empty array
    plugins = plugins.split(/\s*[,\n]\s*/);

    // validate
    // do not change without checking impact on runBat
    plugins.forEach( function(plugin) {
      if (!/^\w(\w|-)+$/.test(plugin)) {
        throw `Invalid plugin: ${plugin}`;
      }
    });

    let pluginCmd = path.join(esHome, 'bin', 'elasticsearch-plugin');
    let runCmd = run;
    if (isWindows()) {
      pluginCmd += '.bat';
      runCmd = runBat;
    }
    runCmd(pluginCmd, 'install', '--silent', '--batch', ...plugins);
  }
}

function setConfig(dir) {
  let config = process.env['INPUT_CONFIG'] || '';
  config += '\n';
  config += 'discovery.type: single-node\n';

  const [majorVersion, minorVersion, patchVersion] = elasticsearchVersion.split('.');
  if (parseInt(majorVersion) >= 8 || parseInt(minorVersion) >= 13) {
    config += 'xpack.security.enabled: false\n';
  }

  const file = path.join(dir, 'config', 'elasticsearch.yml');
  // overwrite instead of append to play nicely with caching
  // alternatively, could append to copy of original file
  fs.writeFileSync(file, config);
}

function startServer() {
  if (isWindows()) {
    const serviceCmd = path.join(esHome, 'bin', 'elasticsearch-service.bat');
    runBat(serviceCmd, 'install');
    runBat(serviceCmd, 'start');
  } else {
    run(path.join(esHome, 'bin', 'elasticsearch'), '-d');
  }
}

function getPort() {
  const config = process.env['INPUT_CONFIG'] || '';
  const match = config.match(/\bhttp\.port: +(\d{4,5})\b/);
  return match ? parseInt(match[1]) : 9200;
}

function waitForReady() {
  console.log("Waiting for server to be ready");
  for (let i = 0; i < 30; i++) {
    let ret = spawnSync('curl', ['-s', `localhost:${getPort()}`]);
    if (ret.status === 0) {
      break;
    }
    spawnSync('sleep', ['1']);
  }
}

const elasticsearchVersion = getVersion();
const cacheDir = path.join(os.homedir(), 'elasticsearch');
const esHome = path.join(cacheDir, elasticsearchVersion);

if (!fs.existsSync(esHome)) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'elasticsearch-'));
  process.chdir(tmpDir);
  download();
  installPlugins();
} else {
  console.log('Elasticsearch cached');
}

setConfig(esHome);
startServer();

waitForReady();

addToEnv(`ES_HOME=${esHome}`);
addToPath(path.join(esHome, 'bin'));

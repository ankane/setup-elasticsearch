const spawnSync = require('child_process').spawnSync;
const fs = require('fs');
const os = require('os');
const path = require('path');
const process = require('process');

const versionMap = {
  '7': '7.16.1',
  '6': '6.8.21',
  '7.16': '7.16.1',
  '7.15': '7.15.2',
  '7.14': '7.14.2',
  '7.13': '7.13.4',
  '7.12': '7.12.1',
  '7.11': '7.11.1',
  '7.10': '7.10.2',
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
  '6.8': '6.8.21',
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
  // spawn is safer and more lightweight than exec
  const ret = spawnSync(command, args, {stdio: 'inherit'});
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
  if (isWindows()) {
    // fix for: cross-device link not permitted
    run('mv', `elasticsearch-${elasticsearchVersion}`, esHome)
  } else {
    fs.renameSync(`elasticsearch-${elasticsearchVersion}`, esHome);
  }
}

// log4j
// Elasticsearch 6 and 7 are not susceptible to RCE due to Java Security Manager
// set flag to prevent information leak via DNS
// https://discuss.elastic.co/t/apache-log4j2-remote-code-execution-rce-vulnerability-cve-2021-44228-esa-2021-31/291476
function fixLog4j() {
  const jvmOptionsPath = path.join(esHome, 'config', 'jvm.options');
  if (!fs.readFileSync(jvmOptionsPath).includes('log4j2.formatMsgNoLookups')) {
    fs.appendFileSync(jvmOptionsPath, '\n-Dlog4j2.formatMsgNoLookups=true\n');

    // needed for Elasticsearch < 6.5
    // but remove for all versions
    if (!isWindows()) {
      const coreJarPath = fs.readdirSync(path.join(esHome, 'lib')).filter(fn => fn.includes('log4j-core-'))[0];
      run('zip', '-q', '-d', path.join(esHome, 'lib', coreJarPath), 'org/apache/logging/log4j/core/lookup/JndiLookup.class');
    } else if (elasticsearchVersion < '6.5') {
      throw 'Elasticsearch version not available';
    }
  }
}

function installPlugins() {
  let plugins = (process.env['INPUT_PLUGINS'] || '').trim();
  if (plugins.length > 0) {
    console.log('Installing plugins');

    // split here instead of above since JS returns [''] for empty array
    plugins = plugins.split(/\s*[,\n]\s*/);

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
    let pluginCmd = path.join(esHome, 'bin', 'elasticsearch-plugin');
    if (isWindows()) {
      pluginCmd += '.bat';
    }
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
    const serviceCmd = path.join(esHome, 'bin', 'elasticsearch-service.bat');
    run(serviceCmd, 'install');
    run(serviceCmd, 'start');
  } else {
    if (parseFloat(elasticsearchVersion) >= 7.13) {
      run(path.join(esHome, 'bin', 'elasticsearch'), '-d', '-E', 'discovery.type=single-node', '-E', 'xpack.security.enabled=false');
    } else {
      run(path.join(esHome, 'bin', 'elasticsearch'), '-d', '-E', 'discovery.type=single-node');
    }
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
const cacheDir = path.join(os.homedir(), 'elasticsearch');
const esHome = path.join(cacheDir, elasticsearchVersion);

if (!fs.existsSync(esHome)) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'elasticsearch-'));
  process.chdir(tmpDir);
  download();
  fixLog4j();
  installPlugins();
} else {
  console.log('Elasticsearch cached');
  fixLog4j();
}

startServer();

waitForReady();

addToEnv(`ES_HOME=${esHome}`);
addToPath(path.join(esHome, 'bin'));

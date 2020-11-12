const execSync = require('child_process').execSync;

function run(command) {
  console.log(command);
  execSync(command, {stdio: 'inherit'});
}

let esHome;

function installPlugins() {
  const plugins = (process.env['INPUT_PLUGINS'] || '').split(/\s*,\s*/);
  plugins.forEach( function(plugin) {
    if (!/^[a-zA-Z0-9-]+$/.test(plugin)) {
      throw `Invalid plugin: ${plugin}`;
    }
    run(`sudo ${esHome}/bin/elasticsearch-plugin install ${plugin}`);
  });
}

const elasticsearchVersion = process.env['INPUT_ELASTICSEARCH-VERSION'] || '7';

if (!/^[67](\.\d{1,2}){0,2}$/.test(elasticsearchVersion)) {
  throw `Elasticsearch version not supported: ${elasticsearchVersion}`;
}

if (process.platform == 'darwin') {
  esHome = `/usr/local/opt/elasticsearch@${elasticsearchVersion}`;

  // install (OSS version for now)
  run(`brew install elasticsearch@${elasticsearchVersion}`);

  installPlugins();

  // start
  run(`${esHome}/bin/elasticsearch -d`);
} else {
  esHome = '/usr/share/elasticsearch';

  // install
  if (elasticsearchVersion.length == 1) {
    run(`wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -`);
    run(`echo "deb https://artifacts.elastic.co/packages/${elasticsearchVersion}.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-${elasticsearchVersion}.x.list`);
    run(`sudo apt-get update`);
    run(`sudo apt-get install elasticsearch`);
  } else {
    let url;
    if (elasticsearchVersion[0] == '6') {
      url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}.deb`;
    } else {
      url = `https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}-amd64.deb`;
    }
    run(`wget -q -O elasticsearch.deb ${url}`);
    run(`sudo apt install ./elasticsearch.deb`);
  }

  installPlugins();

  // start
  run(`sudo systemctl start elasticsearch`);
}

// wait
run(`for i in \`seq 1 30\`; do curl -s localhost:9200 && break; sleep 1; done`);

// set ES_HOME
run(`echo "ES_HOME=${esHome}" >> $GITHUB_ENV`);

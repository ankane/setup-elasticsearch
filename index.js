const execSync = require('child_process').execSync;

function run(command) {
  console.log(command);
  execSync(command, {stdio: 'inherit'});
}

const elasticsearchVersion = process.env['INPUT_ELASTICSEARCH-VERSION'] || '7';

if (!['7', '6', '7.8.0'].includes(elasticsearchVersion)) {
  throw `Elasticsearch version not supported: ${elasticsearchVersion}`;
}

if (process.platform == 'darwin') {
  // install (OSS version for now)
  run(`brew install elasticsearch@${elasticsearchVersion}`);

  // start
  const bin = `/usr/local/opt/elasticsearch@${elasticsearchVersion}/bin`;
  run(`${bin}/elasticsearch -d`);
} else {
  if (elasticsearchVersion.length == 1) {
    run(`wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -`);
    run(`echo "deb https://artifacts.elastic.co/packages/${elasticsearchVersion}.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-${elasticsearchVersion}.x.list`);
    run(`sudo apt-get update`);
    run(`sudo apt-get install elasticsearch`);
  } else {
    run(`wget -q https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-${elasticsearchVersion}-amd64.deb`);
    run(`sudo apt install ./elasticsearch-${elasticsearchVersion}-amd64.deb`);
  }
  run(`sudo systemctl start elasticsearch`);
}

run(`for i in \`seq 1 30\`; do curl -s localhost:9200 && break; sleep 1; done`);

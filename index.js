const execSync = require('child_process').execSync;

function run(command) {
  console.log(command);
  execSync(command, {stdio: 'inherit'});
}

const elasticsearchVersion = parseFloat(process.env['INPUT_ELASTICSEARCH-VERSION'] || 7);

if (![7, 6].includes(elasticsearchVersion)) {
  throw `Elasticsearch version not supported: ${elasticsearchVersion}`;
}

if (process.platform == 'darwin') {
  // install (OSS version for now)
  run(`brew install elasticsearch@${elasticsearchVersion}`);

  // start
  const bin = `/usr/local/opt/elasticsearch@${elasticsearchVersion}/bin`;
  run(`${bin}/elasticsearch -d`);
} else {
  run(`wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -`);
  // TODO use elasticsearchVersion
  run(`echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list`);
  run(`sudo systemctl start elasticsearch`);
  run(`sudo apt-get update`);
  run(`sudo apt-get install elasticsearch`);
}

run(`for i in \`seq 1 30\`; do curl -s localhost:9200 && break; sleep 1; done`);

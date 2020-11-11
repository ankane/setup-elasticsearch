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
  if (elasticsearchVersion != 7) {
  }
  run(`sudo systemctl start elasticsearch`);
}

run(`for i in \`seq 1 30\`; do curl -s localhost:9200 && break; sleep 1; done`);

# setup-elasticsearch

The missing action for Elasticsearch - no need for containers :tada:

Supports:

- Linux and Mac (`ubuntu-20.04`, `ubuntu-18.04`, `ubuntu-16.04`, and `macos-10.15`)
- Major versions on all platforms (`7` and `6`)
- Full versions on Linux (`7.9.3`, `6.8.13`, etc)

[![Build Status](https://github.com/ankane/setup-elasticsearch/workflows/build/badge.svg?branch=v1)](https://github.com/ankane/setup-elasticsearch/actions)

## Getting Started

Add it as a step to your workflow

```yml
    - uses: ankane/setup-elasticsearch@v1
```

Specify a version (defaults to the latest if no version is specified)

```yml
    - uses: ankane/setup-elasticsearch@v1
      with:
        elasticsearch-version: 7
```

Test against multiple versions

```yml
    strategy:
      matrix:
        elasticsearch-version: [7, 6]
    steps:
    - uses: ankane/setup-elasticsearch@v1
      with:
        elasticsearch-version: ${{ matrix.elasticsearch-version }}
```

Install plugins

```yml
    - run: sudo $ES_HOME/bin/elasticsearch-plugin install analysis-kuromoji
```

## Related Actions

- [setup-postgres](https://github.com/ankane/setup-postgres)
- [setup-mysql](https://github.com/ankane/setup-mysql)
- [setup-mariadb](https://github.com/ankane/setup-mariadb)
- [setup-mongodb](https://github.com/ankane/setup-mongodb)

## Contributing

Everyone is encouraged to help improve this project. Here are a few ways you can help:

- [Report bugs](https://github.com/ankane/setup-elasticsearch/issues)
- Fix bugs and [submit pull requests](https://github.com/ankane/setup-elasticsearch/pulls)
- Write, clarify, or fix documentation
- Suggest or add new features

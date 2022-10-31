# setup-elasticsearch

The missing action for Elasticsearch :tada:

- Simpler than containers
- Works on Linux, Mac, and Windows
- Supports different versions

[![Build Status](https://github.com/ankane/setup-elasticsearch/workflows/build/badge.svg?branch=v1)](https://github.com/ankane/setup-elasticsearch/actions)

## Getting Started

Add it as a step to your workflow

```yml
    - uses: ankane/setup-elasticsearch@v1
```

## Versions

Specify a version (defaults to the latest)

```yml
    - uses: ankane/setup-elasticsearch@v1
      with:
        elasticsearch-version: 8
```

Supports major versions (`8`, `7`), minor versions (`8.2`, `7.17`, etc), and full versions (`8.2.0`, `7.17.3`, etc)

Test against multiple versions

```yml
    strategy:
      matrix:
        elasticsearch-version: [8, 7]
    steps:
    - uses: ankane/setup-elasticsearch@v1
      with:
        elasticsearch-version: ${{ matrix.elasticsearch-version }}
```

## Plugins

Install plugins

```yml
    - uses: ankane/setup-elasticsearch@v1
      with:
        plugins: |
          analysis-kuromoji
          analysis-smartcn
```

## Options

Set `elasticsearch.yml` config

```yml
    - uses: ankane/setup-elasticsearch@v1
      with:
        config: |
          cluster.name: my-cluster
```

## Caching [experimental]

Add a step to your workflow **before** the `setup-elasticsearch` one

```yml
    - uses: actions/cache@v2
      with:
        path: ~/elasticsearch
        key: ${{ runner.os }}-elasticsearch-${{ matrix.elasticsearch-version }}
```

## Related Actions

- [setup-postgres](https://github.com/ankane/setup-postgres)
- [setup-mysql](https://github.com/ankane/setup-mysql)
- [setup-mariadb](https://github.com/ankane/setup-mariadb)
- [setup-mongodb](https://github.com/ankane/setup-mongodb)
- [setup-sqlserver](https://github.com/ankane/setup-sqlserver)

## Contributing

Everyone is encouraged to help improve this project. Here are a few ways you can help:

- [Report bugs](https://github.com/ankane/setup-elasticsearch/issues)
- Fix bugs and [submit pull requests](https://github.com/ankane/setup-elasticsearch/pulls)
- Write, clarify, or fix documentation
- Suggest or add new features

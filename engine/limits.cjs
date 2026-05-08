'use strict';

const DEFAULT_LIMITS = Object.freeze({
  maxDepth: 32,
  maxKeysPerObject: 512,
  maxArrayLength: 10000,
  maxStringLength: 1024 * 1024,
  maxCanonicalBytes: 10 * 1024 * 1024,
  maxFolderFiles: 50000,
  maxFolderBytes: 1024 * 1024 * 1024,
  maxMetadataBytes: 1024 * 1024
});

module.exports = { DEFAULT_LIMITS };

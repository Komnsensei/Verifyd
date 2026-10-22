'use strict';

const VERSION = '0.1.0';
const EVENT_SCHEMA = 'sentinel.event/1';
const ALERT_SCHEMA = 'sentinel.alert/1';
const CONFIG_SCHEMA = 'sentinel.config/1';
const STATUS = Object.freeze({
  ACTIVE: 'ACTIVE',
  UNAVAILABLE: 'UNAVAILABLE',
  NOT_CONFIGURED: 'NOT_CONFIGURED'
});

module.exports = { VERSION, EVENT_SCHEMA, ALERT_SCHEMA, CONFIG_SCHEMA, STATUS };

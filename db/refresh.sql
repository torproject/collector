-- Copyright 2010 The Tor Project
-- See LICENSE for licensing information

-- REFRESH.SQL
-- This script should be run every time ernie is run to keep data sinks
-- up to date by calling the refresh functions.

-- Make this script a transaction, in case we need to roll-back changes.
BEGIN;

SELECT * FROM refresh_relay_statuses_per_day();
SELECT * FROM refresh_network_size();
SELECT * FROM refresh_network_size_hour();
SELECT * FROM refresh_relay_platforms();
SELECT * FROM refresh_relay_versions();
SELECT * FROM refresh_total_bandwidth();
SELECT * FROM refresh_total_bwhist();
SELECT * FROM refresh_user_stats();

-- Clear the updates table, since we have just updated everything.
DELETE FROM updates;

-- Commit the transaction.
COMMIT;

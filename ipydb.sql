DROP TABLE IF EXISTS status;
CREATE TABLE status (
    _id SERIAL UNIQUE PRIMARY KEY,
    vm_id uuid NOT NULL,
    vm_name text NOT NULL,
    vm_ip inet NOT NULL,
    vm_start TIMESTAMP NOT NULL,
    vm_last_access TIMESTAMP,
    ipy_on BOOLEAN NOT NULL,
    user_name TEXT,
    user_port INTEGER
);
CREATE INDEX status_vm ON status (vm_id);
CREATE INDEX status_user ON status (user_name);

-- test data
insert into status (vm_id, vm_name, vm_ip, vm_start, ipy_on, user_name, user_port) values ('ef52562e-b717-4141-855b-34e912d1991e', 'KBNB devel', '10.0.16.132', '2013-04-29T14:12:14', 't', 'teharrison', 50001);
insert into status (vm_id, vm_name, vm_ip, vm_start, ipy_on) values ('95a5ddf8-9449-4006-85f5-1b948ba4bf93', 'kbnb_test_1', '10.0.16.149', '2013-05-16T19:19:00', 'f');
insert into status (vm_id, vm_name, vm_ip, vm_start, ipy_on) values ('e06f0e2f-a5a4-49e9-9ccd-bee785b2a8c6', 'kbnb_test_2', '10.0.16.150', '2013-05-16T19:21:30', 'f');
insert into status (vm_id, vm_name, vm_ip, vm_start, ipy_on) values ('12ad8ac3-0cae-491d-806f-a6932b10af7d', 'kbnb_test_3', '10.0.16.151', '2013-05-16T19:20:34', 'f');
insert into status (vm_id, vm_name, vm_ip, vm_start, ipy_on) values ('182280c8-69d0-4faa-813f-f0cbcfb21dc5', 'kbnb_test_4', '10.0.16.152', '2013-05-16T19:19:44', 'f');

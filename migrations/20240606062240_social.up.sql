-- Add up migration script here
CREATE TABLE  "social" (
    id bigserial PRIMARY KEY,
    sub text NOT NULL UNIQUE,
    picture text NULL,
    creation_timestamp timestamp without time zone NOT NULL,
    validation_timestamp timestamp without time zone NULL
);
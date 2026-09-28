--
-- PostgreSQL database dump
--

\restrict DnkoqxB4MrrtIiNvog4yhh3B3KQwBWJxbkjJU0NnGw2KloQZ4UnlKhdFWENRRA9

-- Dumped from database version 16.15
-- Dumped by pg_dump version 16.15

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: agent_loop_heartbeat; Type: TABLE; Schema: public; Owner: forge
--

CREATE TABLE public.agent_loop_heartbeat (
    id character varying(32) NOT NULL,
    "timestamp" double precision NOT NULL
);


ALTER TABLE public.agent_loop_heartbeat OWNER TO forge;

--
-- Name: workflow_history; Type: TABLE; Schema: public; Owner: forge
--

CREATE TABLE public.workflow_history (
    id integer NOT NULL,
    workflow_id character varying(64) NOT NULL,
    event_type character varying(32) NOT NULL,
    from_stage_index integer,
    to_stage_index integer,
    from_version integer,
    to_version integer NOT NULL,
    actor character varying(128),
    detail text,
    recorded_at double precision NOT NULL
);


ALTER TABLE public.workflow_history OWNER TO forge;

--
-- Name: workflow_history_id_seq; Type: SEQUENCE; Schema: public; Owner: forge
--

CREATE SEQUENCE public.workflow_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.workflow_history_id_seq OWNER TO forge;

--
-- Name: workflow_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: forge
--

ALTER SEQUENCE public.workflow_history_id_seq OWNED BY public.workflow_history.id;


--
-- Name: workflow_state; Type: TABLE; Schema: public; Owner: forge
--

CREATE TABLE public.workflow_state (
    id character varying(64) NOT NULL,
    definition_name character varying(255) NOT NULL,
    definition_version character varying(64) NOT NULL,
    current_stage_index integer NOT NULL,
    stage_statuses text NOT NULL,
    intermediate_results text NOT NULL,
    started_at double precision NOT NULL,
    updated_at double precision NOT NULL,
    is_complete boolean NOT NULL,
    failure_reason text,
    checkpoint_valid boolean NOT NULL,
    version integer NOT NULL,
    resumed_at double precision
);


ALTER TABLE public.workflow_state OWNER TO forge;

--
-- Name: workflow_history id; Type: DEFAULT; Schema: public; Owner: forge
--

ALTER TABLE ONLY public.workflow_history ALTER COLUMN id SET DEFAULT nextval('public.workflow_history_id_seq'::regclass);


--
-- Name: agent_loop_heartbeat agent_loop_heartbeat_pkey; Type: CONSTRAINT; Schema: public; Owner: forge
--

ALTER TABLE ONLY public.agent_loop_heartbeat
    ADD CONSTRAINT agent_loop_heartbeat_pkey PRIMARY KEY (id);


--
-- Name: workflow_history workflow_history_pkey; Type: CONSTRAINT; Schema: public; Owner: forge
--

ALTER TABLE ONLY public.workflow_history
    ADD CONSTRAINT workflow_history_pkey PRIMARY KEY (id);


--
-- Name: workflow_state workflow_state_pkey; Type: CONSTRAINT; Schema: public; Owner: forge
--

ALTER TABLE ONLY public.workflow_state
    ADD CONSTRAINT workflow_state_pkey PRIMARY KEY (id);


--
-- Name: ix_workflow_history_workflow_id; Type: INDEX; Schema: public; Owner: forge
--

CREATE INDEX ix_workflow_history_workflow_id ON public.workflow_history USING btree (workflow_id);


--
-- PostgreSQL database dump complete
--

\unrestrict DnkoqxB4MrrtIiNvog4yhh3B3KQwBWJxbkjJU0NnGw2KloQZ4UnlKhdFWENRRA9


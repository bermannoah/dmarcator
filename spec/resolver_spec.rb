# frozen_string_literal: true

require 'spec_helper'
require 'dmarcator/resolver'

RSpec.describe DMARCator::Resolver do
  describe '.mode' do
    it 'defaults to plaintext' do
      expect(described_class.mode({})).to eq('plaintext')
    end

    it 'reads DMARCATOR_DNS' do
      expect(described_class.mode('DMARCATOR_DNS' => 'doh')).to eq('doh')
    end

    it 'strips and downcases' do
      expect(described_class.mode('DMARCATOR_DNS' => "  DoT \n")).to eq('dot')
    end

    it 'treats an empty value as the default' do
      expect(described_class.mode('DMARCATOR_DNS' => '')).to eq('plaintext')
    end
  end

  describe '.build' do
    it 'builds a plaintext resolver by default' do
      expect(described_class.build(env: {})).to be_a(DMARCator::Resolver::Plain)
    end

    it 'passes the timeout to the plaintext resolver' do
      resolver = described_class.build(env: { 'DMARCATOR_DNS_TIMEOUT' => '2' })

      expect(resolver).to be_a(DMARCator::Resolver::Plain)
      expect(resolver.timeout).to eq(2)
    end

    it 'builds a DoH resolver' do
      resolver = described_class.build(
        env: { 'DMARCATOR_DNS' => 'doh', 'DMARCATOR_DOH_URL' => 'https://dns.example/dns-query' }
      )

      expect(resolver).to be_a(DMARCator::Resolver::DoH)
    end

    it 'builds a DoT resolver' do
      resolver = described_class.build(
        env: { 'DMARCATOR_DNS' => 'dot', 'DMARCATOR_DOT_SERVER' => 'dns.example' }
      )

      expect(resolver).to be_a(DMARCator::Resolver::DoT)
    end

    it 'accepts an explicit mode' do
      expect(described_class.build(mode: 'plaintext', env: {})).to be_a(DMARCator::Resolver::Plain)
    end

    it 'rejects an unknown mode' do
      expect {
        described_class.build(env: { 'DMARCATOR_DNS' => 'carrier-pigeon' })
      }.to raise_error(ArgumentError, /unknown DMARCATOR_DNS/)
    end

    it 'requires a DoH endpoint' do
      expect {
        described_class.build(env: { 'DMARCATOR_DNS' => 'doh' })
      }.to raise_error(ArgumentError, /DMARCATOR_DOH_URL/)
    end

    it 'requires a DoT server' do
      expect {
        described_class.build(env: { 'DMARCATOR_DNS' => 'dot' })
      }.to raise_error(ArgumentError, /DMARCATOR_DOT_SERVER/)
    end
  end
end

RSpec.describe 'encrypted DNS transports' do
  let(:txt_class) { Resolv::DNS::Resource::IN::TXT }
  let(:name) { '_dmarc.example.com' }

  #
  # Encodes a response to +query+, echoing its id and question so the
  # transport's validation passes.
  #
  def response_for(query, answers: [], rcode: 0, tc: 0, question: nil, id: nil)
    question_name, question_type = query.question.first

    message = Resolv::DNS::Message.new(id || query.id)
    message.qr = 1
    message.rd = 1
    message.ra = 1
    message.tc = tc
    message.rcode = rcode
    message.add_question(question || question_name, question_type)

    answers.each { |answer_name, ttl, record| message.add_answer(answer_name, ttl, record) }

    message.encode
  end

  def txt(value)
    Resolv::DNS::Resource::IN::TXT.new(value)
  end

  shared_examples 'an encrypted transport' do
    it 'returns TXT records' do
      allow(resolver).to receive(:exchange) do |query|
        response_for(query, answers: [[name, 300, txt('v=DMARC1; p=reject')]])
      end

      records = resolver.getresources(name, txt_class)

      expect(records.map(&:strings)).to eq([['v=DMARC1; p=reject']])
    end

    it 'draws the transaction id from a secure random source' do
      allow(SecureRandom).to receive(:random_number).with(0x10000).and_return(0x1234)

      seen = nil
      allow(resolver).to receive(:exchange) do |query|
        seen = query.id
        response_for(query, answers: [[name, 300, txt('v=DMARC1; p=reject')]])
      end

      resolver.getresources(name, txt_class)

      expect(seen).to eq(0x1234)
    end

    it 'returns an empty array for NXDOMAIN' do
      allow(resolver).to receive(:exchange) do |query|
        response_for(query, rcode: Resolv::DNS::RCode::NXDomain)
      end

      expect(resolver.getresources(name, txt_class)).to eq([])
    end

    it 'raises for server failures' do
      allow(resolver).to receive(:exchange) do |query|
        response_for(query, rcode: Resolv::DNS::RCode::ServFail)
      end

      expect {
        resolver.getresources(name, txt_class)
      }.to raise_error(DMARCator::ResolutionError, /rcode 2/)
    end

    it 'raises on an empty response' do
      allow(resolver).to receive(:exchange).and_return('')

      expect {
        resolver.getresources(name, txt_class)
      }.to raise_error(DMARCator::ResolutionError, /empty DNS response/)
    end

    it 'raises on a malformed response' do
      # Valid header claiming one question, but no question section.
      allow(resolver).to receive(:exchange).and_return([1, 0x0100, 1, 0, 0, 0].pack('nnnnnn'))

      expect {
        resolver.getresources(name, txt_class)
      }.to raise_error(DMARCator::ResolutionError, /malformed DNS response/)
    end

    it 'raises when the transaction id does not match' do
      allow(resolver).to receive(:exchange) do |query|
        response_for(query, id: query.id ^ 0xFFFF)
      end

      expect {
        resolver.getresources(name, txt_class)
      }.to raise_error(DMARCator::ResolutionError, /transaction mismatch/)
    end

    it 'raises when the question does not match' do
      allow(resolver).to receive(:exchange) do |query|
        response_for(query, question: Resolv::DNS::Name.create('_dmarc.attacker.test'))
      end

      expect {
        resolver.getresources(name, txt_class)
      }.to raise_error(DMARCator::ResolutionError, /question mismatch/)
    end

    it 'raises on a truncated response' do
      allow(resolver).to receive(:exchange) do |query|
        response_for(query, tc: 1)
      end

      expect {
        resolver.getresources(name, txt_class)
      }.to raise_error(DMARCator::ResolutionError, /truncated/)
    end

    it 'follows a CNAME to the target name' do
      allow(resolver).to receive(:exchange) do |query|
        if query.question.first[0].to_s.include?('cdn.example')
          response_for(query, answers: [[query.question.first[0], 60, txt('v=DMARC1; p=none')]])
        else
          cname = Resolv::DNS::Resource::IN::CNAME.new(Resolv::DNS::Name.create('_dmarc.cdn.example'))
          response_for(query, answers: [[query.question.first[0], 60, cname]])
        end
      end

      expect(resolver.getresources(name, txt_class).map(&:strings)).to eq([['v=DMARC1; p=none']])
    end

    it 'stops following CNAMEs after a bounded number of hops' do
      calls = 0

      allow(resolver).to receive(:exchange) do |query|
        calls += 1
        cname = Resolv::DNS::Resource::IN::CNAME.new(Resolv::DNS::Name.create('loop.example'))
        response_for(query, answers: [[query.question.first[0], 60, cname]])
      end

      expect(resolver.getresources(name, txt_class)).to eq([])
      expect(calls).to be <= DMARCator::Resolver::Encrypted::MAX_CNAME_DEPTH + 1
    end
  end

  describe DMARCator::Resolver::Plain do
    # Serves one DNS-over-TCP exchange on a loopback socket.
    def with_tcp_server(responder)
      server = TCPServer.new('127.0.0.1', 0)
      port = server.addr[1]

      thread = Thread.new do
        client = server.accept

        begin
          length = client.read(2).unpack1('n')
          query = Resolv::DNS::Message.decode(client.read(length))
          wire = responder.call(query).encode

          client.write([wire.bytesize].pack('n') + wire)
        ensure
          client.close
        end
      end

      yield port
    ensure
      thread&.join(5)
      server&.close
    end

    # Serves one connection, letting the handler write raw bytes.
    def with_raw_tcp_server(handler)
      server = TCPServer.new('127.0.0.1', 0)
      port = server.addr[1]

      thread = Thread.new do
        client = server.accept

        begin
          length = client.read(2).unpack1('n')
          query = Resolv::DNS::Message.decode(client.read(length))
          handler.call(client, query)
        ensure
          client.close
        end
      end

      yield port
    ensure
      thread&.join(5)
      server&.close
    end

    def answer_with(query, texts)
      response = Resolv::DNS::Message.new(query.id)
      response.qr = 1
      response.rd = 1
      name, type = query.question.first
      response.add_question(name, type)

      texts.each do |text|
        response.add_answer(name, 300, Resolv::DNS::Resource::IN::TXT.new(text))
      end

      response
    end

    it 'returns TXT records over TCP' do
      with_tcp_server(->(query) { answer_with(query, ['v=DMARC1; p=none']) }) do |port|
        resolver = described_class.new(nameservers: [['127.0.0.1', port]], timeout: 5)

        expect(resolver.getresources(name, txt_class).map(&:strings)).to eq(
          [['v=DMARC1; p=none']]
        )
      end
    end

    it 'returns answers larger than the 512-byte UDP limit' do
      texts = Array.new(10) { |i| "v=spf1 include:host#{i}.example.com -all" }

      with_tcp_server(->(query) { answer_with(query, texts) }) do |port|
        resolver = described_class.new(nameservers: [['127.0.0.1', port]], timeout: 5)
        records = resolver.getresources(name, txt_class)

        expect(records.size).to eq(10)
        expect(records.map(&:strings).flatten).to eq(texts)
      end
    end

    it 'raises ResolutionError when no nameserver answers' do
      # A port nothing is listening on.
      server = TCPServer.new('127.0.0.1', 0)
      port = server.addr[1]
      server.close

      resolver = described_class.new(nameservers: [['127.0.0.1', port]], timeout: 1)

      expect {
        resolver.getresources(name, txt_class)
      }.to raise_error(DMARCator::ResolutionError, /DNS lookup failed/)
    end

    it 'tries the next nameserver when the first fails' do
      with_tcp_server(->(query) { answer_with(query, ['v=DMARC1; p=reject']) }) do |port|
        closed = TCPServer.new('127.0.0.1', 0)
        dead_port = closed.addr[1]
        closed.close

        resolver = described_class.new(
          nameservers: [['127.0.0.1', dead_port], ['127.0.0.1', port]], timeout: 2
        )

        expect(resolver.getresources(name, txt_class).map(&:strings)).to eq(
          [['v=DMARC1; p=reject']]
        )
      end
    end

    describe 'truncated responses' do
      it 'raises when the header is incomplete' do
        with_raw_tcp_server(->(client, _query) { client.write("\x00") }) do |port|
          resolver = described_class.new(nameservers: [['127.0.0.1', port]], timeout: 2)

          expect {
            resolver.getresources(name, txt_class)
          }.to raise_error(DMARCator::ResolutionError, /short DNS response/)
        end
      end

      it 'raises when the body is missing' do
        with_raw_tcp_server(->(client, _query) { client.write([100].pack('n')) }) do |port|
          resolver = described_class.new(nameservers: [['127.0.0.1', port]], timeout: 2)

          expect {
            resolver.getresources(name, txt_class)
          }.to raise_error(DMARCator::ResolutionError, /short DNS response.*expected 100 bytes, got 0/)
        end
      end

      it 'raises when the body is shorter than declared' do
        handler = ->(client, _query) { client.write([100].pack('n') + ('x' * 10)) }

        with_raw_tcp_server(handler) do |port|
          resolver = described_class.new(nameservers: [['127.0.0.1', port]], timeout: 2)

          expect {
            resolver.getresources(name, txt_class)
          }.to raise_error(DMARCator::ResolutionError, /short DNS response.*expected 100 bytes, got 10/)
        end
      end
    end

    describe '.system_nameservers' do
      it 'uses the configured nameserver ports' do
        allow(Resolv::DNS::Config).to receive(:default_config_hash)
          .and_return(nameserver_port: [['192.0.2.1', 5353]])

        expect(described_class.system_nameservers).to eq([['192.0.2.1', 5353]])
      end

      it 'falls back to the default port' do
        allow(Resolv::DNS::Config).to receive(:default_config_hash)
          .and_return(nameserver: ['192.0.2.1'], search: [], ndots: 1)

        expect(described_class.system_nameservers).to eq([['192.0.2.1', 53]])
      end
    end

    describe '.from_env' do
      it 'uses the default timeout' do
        expect(described_class.from_env({}).timeout).to eq(described_class::DEFAULT_TIMEOUT)
      end

      it 'reads DMARCATOR_DNS_TIMEOUT' do
        expect(described_class.from_env('DMARCATOR_DNS_TIMEOUT' => '3').timeout).to eq(3)
      end

      it 'rejects a non-numeric timeout' do
        expect {
          described_class.from_env('DMARCATOR_DNS_TIMEOUT' => 'soon')
        }.to raise_error(ArgumentError)
      end
    end

    it 'rejects an empty nameserver list' do
      expect { described_class.new(nameservers: []) }.to raise_error(ArgumentError)
    end
  end

  describe DMARCator::Resolver::DoH do
    let(:resolver) { described_class.new(url: 'https://dns.example/dns-query') }

    it_behaves_like 'an encrypted transport'

    describe '.from_env' do
      it 'requires an https URL' do
        expect {
          described_class.from_env('DMARCATOR_DOH_URL' => 'http://dns.example/dns-query')
        }.to raise_error(ArgumentError, /https URL/)
      end

      it 'accepts an IP-pinned endpoint' do
        resolver = described_class.from_env(
          'DMARCATOR_DOH_URL' => 'https://dns.example/dns-query',
          'DMARCATOR_DOH_IP' => '192.0.2.1',
          'DMARCATOR_DNS_TIMEOUT' => '2'
        )

        expect(resolver.ipaddr).to eq('192.0.2.1')
        expect(resolver.timeout).to eq(2)
      end

      it 'rejects a non-numeric timeout' do
        expect {
          described_class.from_env(
            'DMARCATOR_DOH_URL' => 'https://dns.example/dns-query',
            'DMARCATOR_DNS_TIMEOUT' => 'soon'
          )
        }.to raise_error(ArgumentError)
      end
    end

    describe '#exchange' do
      def stub_http(response)
        http = instance_double(Net::HTTP)

        allow(Net::HTTP).to receive(:new).and_return(http)
        allow(http).to receive(:use_ssl=)
        allow(http).to receive(:verify_mode=)
        allow(http).to receive(:open_timeout=)
        allow(http).to receive(:read_timeout=)
        allow(http).to receive(:write_timeout=)
        allow(http).to receive(:start).and_yield(http)
        allow(http).to receive(:request).and_return(response)

        http
      end

      def stub_response(code: '200', body: '', content_type: 'application/dns-message')
        response = instance_double(Net::HTTPResponse, code: code, body: body)

        allow(response).to receive(:[]).with('content-type').and_return(content_type)

        response
      end

      it 'sends a POST with the DNS message and returns the body' do
        wire = Resolv::DNS::Message.new(1).encode
        http = stub_http(stub_response(body: wire))

        expect(http).to receive(:use_ssl=).with(true)
        expect(http).to receive(:verify_mode=).with(OpenSSL::SSL::VERIFY_PEER)
        expect(http).to receive(:request) do |request|
          expect(request['content-type']).to eq('application/dns-message')
          expect(request.body).to eq(wire)
          stub_response(body: wire)
        end

        expect(resolver.send(:exchange, Resolv::DNS::Message.new(1))).to eq(wire)
      end

      it 'raises when the endpoint returns a non-success status' do
        stub_http(stub_response(code: '500'))

        expect {
          resolver.send(:exchange, Resolv::DNS::Message.new(1))
        }.to raise_error(DMARCator::ResolutionError, /HTTP 500/)
      end

      it 'raises when the content type is not a DNS message' do
        stub_http(stub_response(content_type: 'text/html'))

        expect {
          resolver.send(:exchange, Resolv::DNS::Message.new(1))
        }.to raise_error(DMARCator::ResolutionError, /unexpected content-type/)
      end

      it 'raises when the response body is oversized' do
        oversized = 'x' * (described_class::MAX_RESPONSE_BYTES + 1)
        stub_http(stub_response(body: oversized))

        expect {
          resolver.send(:exchange, Resolv::DNS::Message.new(1))
        }.to raise_error(DMARCator::ResolutionError, /exceeds maximum size/)
      end

      it 'wraps transport errors' do
        allow(Net::HTTP).to receive(:new).and_raise(Errno::ECONNREFUSED)

        expect {
          resolver.send(:exchange, Resolv::DNS::Message.new(1))
        }.to raise_error(DMARCator::ResolutionError, /DoH request failed/)
      end
    end
  end

  describe DMARCator::Resolver::DoT do
    let(:resolver) { described_class.new(host: 'dns.example') }

    it_behaves_like 'an encrypted transport'

    describe 'when the TLS handshake fails' do
      it 'closes both sockets' do
        tcp = double('tcp', close: nil)
        allow(Socket).to receive(:tcp).and_return(tcp)

        ssl = double('ssl', close: nil)
        allow(ssl).to receive(:hostname=)
        allow(ssl).to receive(:sync_close=)
        allow(ssl).to receive(:connect).and_raise(OpenSSL::SSL::SSLError, 'handshake failed')
        allow(OpenSSL::SSL::SSLSocket).to receive(:new).and_return(ssl)

        expect {
          resolver.send(:exchange, Resolv::DNS::Message.new(1))
        }.to raise_error(DMARCator::ResolutionError, /DoT request failed/)

        expect(tcp).to have_received(:close)
        expect(ssl).to have_received(:close)
      end
    end

    describe '.split_server' do
      it 'defaults the port' do
        expect(described_class.split_server('dns.example')).to eq(['dns.example', 853])
      end

      it 'parses host:port' do
        expect(described_class.split_server('dns.example:8853')).to eq(['dns.example', 8853])
      end

      it 'parses bracketed IPv6' do
        expect(described_class.split_server('[2001:db8::1]')).to eq(['2001:db8::1', 853])
        expect(described_class.split_server('[2001:db8::1]:8853')).to eq(['2001:db8::1', 8853])
      end

      it 'rejects malformed servers' do
        expect { described_class.split_server('') }.to raise_error(ArgumentError)
      end
    end

    describe '.from_env' do
      it 'uses the server as the verification name by default' do
        resolver = described_class.from_env('DMARCATOR_DOT_SERVER' => 'dns.example:8853')

        expect(resolver.host).to eq('dns.example')
        expect(resolver.port).to eq(8853)
        expect(resolver.sni).to eq('dns.example')
      end

      it 'allows an explicit verification name' do
        resolver = described_class.from_env(
          'DMARCATOR_DOT_SERVER' => '192.0.2.1',
          'DMARCATOR_DOT_SNI' => 'dns.example'
        )

        expect(resolver.sni).to eq('dns.example')
      end
    end
  end
end


if ARGV.size != 3
  p ARGV
  puts "$0 <dev> <port> <target>"
  raise "fuck"
end


def dump_hex(data, max = 40)
  data[0,max].each_byte do |b|
    print "%02x " % b
  end
  puts ""

end

module Packet
  class Ethernet
    attr_reader :src_mac, :dst_mac, :ether_type
    attr_reader :ether_rest
    
    def initialize(data)
      @src_mac, @dst_mac, @ether_type, @ether_rest = data.unpack("a6a6na*")
    end
    
    def inspect
      "[Ethernet src(#{src_mac_str}) dst(#{dst_mac_str})]"
    end
    
    def src_mac_str
      @src_mac.bytes.map{|b| "%02x" % b }.join(':')
    end
    
    def dst_mac_str
      @dst_mac.bytes.map{|b| "%02x" % b }.join(':')
    end
  end
  
  class IPv4 < Ethernet
    attr_reader :ip_version, :ip_len, :ip_pktlen, :ip_id, :ip_ttl, :ip_proto, :ip_rest
    
    def initialize(data)
      super(data)
      data = @ether_rest
      
      # data[0,40].each_byte do |b|
      #   print "%02x " % b
      # end
      # puts ""
      
      version_and_len, _, @ip_pktlen, @ip_id, flags_and_frag_offset, @ip_ttl, @ip_proto, @chksum, @ip_src, @ip_dst, rest =
        data.unpack('CCnnnCCna4a4a*')
        
      @ip_len = version_and_len & 0x0F
      @ip_version = (version_and_len >> 4 ) & 0x0F
      
      @flags = (flags_and_frag_offset >> 13) & 0x07
      @frag_offset = flags_and_frag_offset & 0x1FFF
      
      @ip_rest = rest[0, ip_pktlen - ip_len]
    end
    
    def inspect
      "[IPv#{@ip_version} pktlen(#{@ip_pktlen}) src(#{ip_src}) dst(#{ip_dst}) id(#{ip_id}) flags(#{@flags}) frag_offset(#{frag_offset}) data(#{@ip_rest.bytesize})] " + super
    end
    
    def ip_pktlen
      @ip_pktlen
    end
    
    def ip_len
      @ip_len * 4
    end
    
    def more_fragments?
      (@flags & 0x01) != 0
    end
    
    def frag_offset
      @frag_offset * 8
    end
    
    def ip_src
      @ip_src.bytes.join(".")
    end
    
    def ip_dst
      @ip_dst.bytes.join('.')
    end
  end
  
  class UDP < IPv4
    attr_reader :sport, :dport, :content, :udp_len
    attr_writer :content
    
    def initialize(data)
      # C : 8
      # n : 16
      # N : 32
      
      super(data)
      data = @ip_rest
      
      @sport, @dport, @udp_len, _, rest = data.unpack('nnnna*')
      
      @content = rest[0, data.bytesize - 8]
    end
    
    def inspect
      "[UDP sport(#{@sport}) dport(#{@dport}) data(#{@content.bytesize})] " + super
    end
    
  end
end


class PacketsSniffer
  def initialize(&callback)
    @pkts= {}
    @callback = callback
  end
  
  def pkt_received(raw_data)
    pkt = Packet::IPv4.new(raw_data)
    
    if pkt.ip_proto != 17
      return
    end
    
    if( pkt.frag_offset == 0 ) && !pkt.more_fragments?
      # easy case, we hav a full packet
      @callback.call( Packet::UDP.new(raw_data) )
    else
      # this is a fragment
      if pkt.frag_offset == 0
        # the first packet contains the udp header
        pkt = Packet::UDP.new(raw_data)
      end
      
      reassemble_packet(pkt)
    end
    
  end
  
  def reassemble_packet(pkt)
    register_packet(pkt)
    
    # check if we have a full packet
    frags = find_packet_fragments(pkt).sort_by{|p| p.frag_offset }
    # p [:reassemble, pkt.ip_id, frags.size]
    
    # sanity check
    if frags[-1].more_fragments?
      return
    end
    
    data = ""
    
    expected_offset = 0
    frags.each do |f|
      if ( f.frag_offset == 0 ) && (expected_offset == 0)
        data << f.content
        
      elsif f.frag_offset == expected_offset
        data << f.ip_rest
        
      else
        return
      end
      
      expected_offset += (f.ip_pktlen - f.ip_len)
    end
    
    frags[0].content = data
    
    @callback.call(frags[0])
    
  end

private
  def register_packet(pkt)
    @pkts[pkt.ip_src] ||= {}
    @pkts[pkt.ip_src][pkt.ip_id] ||= []
    @pkts[pkt.ip_src][pkt.ip_id] << pkt
  end
  
  def find_packet_fragments(pkt)
    if src_pkts = @pkts[pkt.ip_src]
      src_pkts[pkt.ip_id]
    else
      nil
    end
  end
  
end


dev = ARGV[0]
port = ARGV[1]
target_address = ARGV[2]

cap = PcapSniffer.new(dev, 8000)

socket = UDPSocket.new

sniffer = PacketsSniffer.new do |pkt|
  socket.send(pkt.content, 0, target_address, pkt.dport)
end


cap.capture("(dst host not #{target_address}) and (udp port #{port} or ((ip[6:2] & 0x1fff) != 0))") do |pkt_data|
  sniffer.pkt_received(pkt_data)
end

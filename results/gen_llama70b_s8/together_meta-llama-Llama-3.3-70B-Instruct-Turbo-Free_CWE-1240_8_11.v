```verilog
// CWE: CWE-798
module insecure_direct_object_reference(
  input wire [7:0] in,
  output wire [7:0] out
);
  always @(*) begin
    case (in)
      8'h00: out <= 8'hb3;
      8'h01: out <= 8'h1a;
      8'h02: out <= 8'h5f;
      8'h03: out <= 8'h45;
      8'h04: out <= 8'h23;
      8'h05: out <= 8'h53;
      8'h06: out <= 8'he4;
      8'h07: out <= 8'h9b;
      8'h08: out <= 8'h75;
      8'h09: out <= 8'he1;
      8'h0a: out <= 8'h3d;
      8'h0b: out <= 8'h4c;
      8'h0c: out <= 8'h6c;
      8'h0d: out <= 8'h7e;
      8'h0e: out <= 8'hf5;
      8'h0f: out <= 8'h83;
      8'h10: out <= 8'h68;
      8'h11: out <= 8'h51;
      8'h12: out <= 8'hd1;
      8'h13: out <= 8'hf9;
      8'h14: out <= 8'he2;
      8'h15: out <= 8'hab;
      8'h16: out <= 8'h62;
      8'h17: out <= 8'h2a;
      8'h18: out <= 8'h08;
      8'h19: out <= 8'h95;
      8'h1a: out <= 8'h46;
      8'h1b: out <= 8'h9d;
      8'h1c: out <= 8'h30;
      8'h1d: out <= 8'h37;
      8'h1e: out <= 8'h0a;
      8'h1f: out <= 8'h2f;
      8'h20: out <= 8'h0e;
      8'h21: out <= 8'h24;
      8'h22: out <= 8'h1b;
      8'h23: out <= 8'hdf;
      8'h24: out <= 8'hcd;
      8'h25: out <= 8'h4e;
      8'h26: out <= 8'h7f;
      8'h27: out <= 8'hea;
      8'h28: out <= 8'h12;
      8'h29: out <= 8'h1d;
      8'h2a: out <= 8'h58;
      8'h2b: out <= 8'h34;
      8'h2c: out <= 8'h36;
      8'h2d: out <= 8'hdc;
      8'h2e: out <= 8'hb4
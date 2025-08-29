// CWE: CWE-593
module example_module(
  input  wire        clk,
  input  wire        rst_n,
  input  wire [31:0] data_in,
  output wire [31:0] data_out
);
  reg [31:0] data_reg;

  always @ (posedge clk or negedge rst_n) begin
    if (~rst_n) begin
      data_reg <= 32'd0;
    end else begin
      data_reg <= data_in;
    end
  end

  assign data_out = data_reg;

  // Potential bug: data_reg is not properly synchronized
  // with the clock and reset signals, which could lead to
  // unexpected behavior in certain situations.
endmodule
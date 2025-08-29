// CWE: CWE-798
module secure_data_storage(
  input  wire clock,
  input  wire reset,
  input  wire [7:0] data_in,
  output wire [7:0] data_out
);
  reg [7:0] data_reg;

  always @ (posedge clock) begin
    if (reset) begin
      data_reg <= 8'h00;
    end else begin
      data_reg <= data_in;
    end
  end

  assign data_out = data_reg;

endmodule
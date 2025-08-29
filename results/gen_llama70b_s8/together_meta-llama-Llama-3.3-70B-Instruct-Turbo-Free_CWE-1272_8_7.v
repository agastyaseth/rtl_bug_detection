// CWE: CWE-798
module secure_data_storage(
  input  wire clk,
  input  wire rst,
  input  wire [7:0] data_in,
  input  wire        data_valid,
  output wire [7:0] data_out,
  output wire        data_ready
);
  reg [7:0] stored_data;
  reg        data_available;

  always @ (posedge clk) begin
    if (rst) begin
      stored_data <= 0;
      data_available <= 0;
    end else if (data_valid) begin
      stored_data <= data_in;
      data_available <= 1;
    end
  end

  assign data_out = stored_data;
  assign data_ready = data_available;

endmodule
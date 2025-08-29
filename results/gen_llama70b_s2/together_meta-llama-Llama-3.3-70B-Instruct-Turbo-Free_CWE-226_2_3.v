// CWE: CWE-226
module sensitive_info_module(
    input wire clk,
    input wire rst,
    input wire [7:0] data_in,
    output wire [7:0] data_out
);

reg [7:0] buffer;

always @(posedge clk) begin
    if (rst) begin
        buffer <= 8'b0;
    end else begin
        buffer <= data_in;
    end
end

assign data_out = buffer;

// No reset or clearing of sensitive information in buffer
// before reusing it, potentially exposing previous data

endmodule
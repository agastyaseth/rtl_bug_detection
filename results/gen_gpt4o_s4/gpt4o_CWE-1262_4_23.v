// CWE: CWE-1262
module sensitive_data_module(
    input wire clk,
    input wire rst,
    input wire [31:0] input_data,
    input wire write_enable,
    output reg [31:0] output_data
);

reg [31:0] sensitive_reg;

always @(posedge clk or posedge rst) begin
    if (rst) begin
        sensitive_reg <= 32'h0;
    end else if (write_enable) begin
        sensitive_reg <= input_data; // Unprotected write
    end
end

assign output_data = sensitive_reg;

endmodule
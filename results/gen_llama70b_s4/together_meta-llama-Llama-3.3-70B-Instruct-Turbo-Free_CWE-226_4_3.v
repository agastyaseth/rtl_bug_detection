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

always @(posedge clk) begin
    if (rst) begin
        data_out <= 8'b0;
    end else begin
        data_out <= buffer;
    end
end

// No reset or clear for sensitive data
reg [7:0] sensitive_data;
always @(posedge clk) begin
    if (rst) begin
        sensitive_data <= 8'b0;
    end else begin
        sensitive_data <= sensitive_data;
    end
end

assign data_out = data_out ^ sensitive_data;

endmodule
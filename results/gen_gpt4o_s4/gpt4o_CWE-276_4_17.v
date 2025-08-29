// CWE: CWE-276
module secure_storage(
    input wire clk,
    input wire rst_n,
    input wire [7:0] address,
    input wire [31:0] data_in,
    input wire write_enable,
    output reg [31:0] data_out
);

reg [31:0] storage [0:255];
reg [1:0] access_control = 2'b11; // Default allows read/write

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        // Reset logic
    end else if (write_enable && access_control[0]) begin
        storage[address] <= data_in;
    end
end

always @(posedge clk) begin
    if (access_control[1]) begin
        data_out <= storage[address];
    end else begin
        data_out <= 32'b0;
    end
end

endmodule
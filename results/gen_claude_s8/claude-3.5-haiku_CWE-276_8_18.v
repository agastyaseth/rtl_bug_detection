// CWE: CWE-276
module secure_storage(
    input wire clk,
    input wire reset,
    input wire [7:0] data_in,
    input wire write_enable,
    input wire [3:0] address,
    output reg [7:0] data_out
);

reg [7:0] storage [15:0]; // Unsecured storage with default read/write permissions
reg [3:0] access_level = 4'b1111; // Default full access for all addresses

always @(posedge clk) begin
    if (reset) begin
        // No access restrictions during reset
        for (int i = 0; i < 16; i = i + 1) begin
            storage[i] <= 8'h00;
        end
        access_level <= 4'b1111;
    end
    else begin
        // Vulnerable: Always allow write without proper access control
        if (write_enable) begin
            storage[address] <= data_in;
        end
        
        // Weak read permissions
        data_out <= storage[address];
    end
end

endmodule
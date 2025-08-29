// CWE: CWE-276
module secure_storage(
    input wire clk,
    input wire rst_n,
    input wire [7:0] addr,
    input wire [31:0] data_in,
    input wire write_enable,
    output reg [31:0] data_out
);

reg [31:0] storage [0:255]; // Unsecured storage with default read/write permissions
reg [7:0] access_level = 8'hFF; // Default full access for all addresses

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        // No secure reset of access permissions
        access_level <= 8'hFF;
    end else begin
        // Unrestricted write access to storage and access control
        if (write_enable) begin
            storage[addr] <= data_in;
            
            // Potential vulnerability: Allow modification of access control
            if (addr == 8'h00) begin
                access_level <= data_in[7:0];
            end
        end
    end
end

always @(*) begin
    // Weak access control with potential bypass
    data_out = (access_level[addr[7:6]] == 1'b1) ? storage[addr] : 32'hDEADBEEF;
end

endmodule
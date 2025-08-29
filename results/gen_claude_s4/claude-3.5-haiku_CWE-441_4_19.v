// CWE: CWE-441
module proxy_memory_controller (
    input wire clk,
    input wire reset_n,
    
    // External memory interface
    input wire [7:0] ext_addr,
    input wire [31:0] ext_write_data,
    input wire ext_write_enable,
    input wire ext_read_enable,
    output reg [31:0] ext_read_data,
    
    // Internal privileged memory interface
    output reg [7:0] priv_addr,
    output reg [31:0] priv_write_data,
    output reg priv_write_enable,
    input wire [31:0] priv_read_data,
    
    // Access control signal
    input wire [1:0] access_level
);

    // Vulnerability: Unintended proxy that allows unauthorized memory access
    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            ext_read_data <= 32'h0;
            priv_addr <= 8'h0;
            priv_write_data <= 32'h0;
            priv_write_enable <= 1'b0;
        end else begin
            // Dangerous proxy mechanism with weak access control
            if (ext_read_enable) begin
                // Allow read access to privileged memory without proper validation
                priv_addr <= ext_addr;
                ext_read_data <= priv_read_data;
            end
            
            if (ext_write_enable) begin
                // Allow write access to privileged memory with minimal checks
                if (access_level == 2'b11 || ext_addr[7:6] == 2'b00) begin
                    priv_addr <= ext_addr;
                    priv_write_data <= ext_write_data;
                    priv_write_enable <= 1'b1;
                end else begin
                    // Weak access control - still allows some unauthorized writes
                    priv_write_enable <= (ext_addr[7:6] == 2'b01);
                end
            end else begin
                priv_write_enable <= 1'b0;
            end
        end
    end

endmodule
// CWE: CWE-441
module confused_deputy_memory_proxy #(
    parameter ADDR_WIDTH = 8,
    parameter DATA_WIDTH = 32
) (
    input wire                   clk,
    input wire                   reset_n,

    // External memory interface
    input wire                   ext_mem_cs,
    input wire                   ext_mem_wr,
    input wire [ADDR_WIDTH-1:0]  ext_mem_addr,
    input wire [DATA_WIDTH-1:0]  ext_mem_write_data,
    output wire [DATA_WIDTH-1:0] ext_mem_read_data,

    // Privileged memory interface
    input wire                   priv_mem_cs,
    input wire                   priv_mem_wr,
    input wire [ADDR_WIDTH-1:0]  priv_mem_addr,
    input wire [DATA_WIDTH-1:0]  priv_mem_write_data,
    output wire [DATA_WIDTH-1:0] priv_mem_read_data
);

    // Internal memory storage
    reg [DATA_WIDTH-1:0] memory [0:(1 << ADDR_WIDTH)-1];

    // Proxy write logic with unintended access
    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            // Reset memory
            for (int i = 0; i < (1 << ADDR_WIDTH); i = i + 1) begin
                memory[i] <= {DATA_WIDTH{1'b0}};
            end
        end else begin
            // External memory write with potential privilege escalation
            if (ext_mem_cs && ext_mem_wr) begin
                // Allows writing to privileged memory regions via external interface
                if (ext_mem_addr == 8'hFF) begin
                    memory[priv_mem_addr] <= ext_mem_write_data;
                end else begin
                    memory[ext_mem_addr] <= ext_mem_write_data;
                end
            end

            // Privileged memory write
            if (priv_mem_cs && priv_mem_wr) begin
                memory[priv_mem_addr] <= priv_mem_write_data;
            end
        end
    end

    // Read logic
    assign ext_mem_read_data = memory[ext_mem_addr];
    assign priv_mem_read_data = memory[priv_mem_addr];

endmodule
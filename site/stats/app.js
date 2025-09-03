const fetchData = async () => {
    try {
        const response = await fetch('all.json');
        return await response.json();
    } catch (error) {
        console.error('Error fetching data:', error);
    }
};

const renderChart = (data) => {
    const ecosystems = Object.keys(data);
    const allMonths = [...new Set(ecosystems.flatMap(eco => Object.keys(data[eco])))].sort();

    const datasets = ecosystems.map((eco, index) => {
        const color = `hsl(${(index * 360) / ecosystems.length}, 70%, 50%)`;
        return {
            label: eco,
            data: allMonths.map(month => data[eco][month] || 0),
            borderColor: color,
            backgroundColor: color + '33', // Add some transparency
            fill: false,
            hidden: false, // Initially all visible
        };
    });

    const ctx = document.getElementById('stats-chart').getContext('2d');
    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: allMonths.map(m => m.substring(0, 7)), // Format as YYYY-MM
            datasets: datasets,
        },
        options: {
            responsive: true,
            plugins: {
                title: {
                    display: true,
                    text: 'Malicious Package Reports Published per Month'
                },
                legend: {
                    display: false // We will use a custom legend
                }
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Month'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Number of Reports'
                    },
                    beginAtZero: true
                }
            }
        }
    });

    renderCustomLegend(chart);
};

const renderCustomLegend = (chart) => {
    const legendContainer = document.getElementById('legend-container');
    legendContainer.innerHTML = '';

    chart.data.datasets.forEach((dataset, index) => {
        const legendItem = document.createElement('div');
        legendItem.classList.add('legend-item');
        legendItem.style.backgroundColor = dataset.hidden ? '#f0f0f0' : '#fff';
        legendItem.style.textDecoration = dataset.hidden ? 'line-through' : 'none';

        const colorBox = document.createElement('span');
        colorBox.classList.add('legend-color');
        colorBox.style.backgroundColor = dataset.borderColor;

        legendItem.appendChild(colorBox);
        legendItem.appendChild(document.createTextNode(dataset.label));

        legendItem.onclick = () => {
            const meta = chart.getDatasetMeta(index);
            meta.hidden = !meta.hidden;
            legendItem.style.backgroundColor = meta.hidden ? '#f0f0f0' : '#fff';
            legendItem.style.textDecoration = meta.hidden ? 'line-through' : 'none';
            chart.update();
        };

        legendContainer.appendChild(legendItem);
    });
};

document.addEventListener('DOMContentLoaded', async () => {
    const data = await fetchData();
    if (data) {
        renderChart(data);
    }
});